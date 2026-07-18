// Request-flow booking endpoint (verify_jwt = false in config.toml).
//
//   POST { session_token, slots: [{start,end} x2-3], party_size? }
//     -> 200 { ok, booking, request } | 400 | 401 | 404 | 409 | 429 | 502
//
// Flow (spec §5.3): an activated voucher's recipient proposes 2-3 slots →
// booking (mode=request, status=pending_provider) + booking_request are
// created atomically (create_booking_request RPC) → the provider gets a
// magic-link email via Resend to accept/decline.
//
// Security model:
// - Caller is authenticated by the stateless HMAC session token minted by
//   activate-voucher (PIN entry is the single auth ceremony; expired token →
//   client re-activates). voucher_id comes from the token, never the body.
// - The provider magic-link token is stored as SHA-256 hash only, with
//   token_expires_at — plaintext lives solely inside the emailed URL
//   (hardened version of the justvibe-ops pattern).
// - Idempotent: a repeat call while a request is pending returns the existing
//   state and only re-sends the email if the previous send failed. Rate
//   limits cap provider email spam (per-voucher + global), counted via events.

import { createClient } from "https://esm.sh/@supabase/supabase-js@2.45.0";
import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { Buffer } from "node:buffer";

// ── Tunables ─────────────────────────────────────────────────────────────────
const MIN_SLOTS = 2, MAX_SLOTS = 3;
const MIN_LEAD_MS = 24 * 60 * 60 * 1000; // provider needs runway
const MAX_HORIZON_MS = 365 * 24 * 60 * 60 * 1000;
const MAX_SLOT_DURATION_MS = 24 * 60 * 60 * 1000;
const PARTY_MIN = 1, PARTY_MAX = 20;
const PROVIDER_TOKEN_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 48h SLA + buffer
const EMAILS_PER_VOUCHER_24H = 3;
const EMAILS_GLOBAL_1H = 100;
const RETRY_AFTER_S = 3600;
const DEFAULT_FROM = "Turile <bookings@turil.ca>"; // override via RESEND_FROM secret
// TODO(phase2): per-provider timezone; Turile providers are Alberta-first for now.
const DISPLAY_TZ = "America/Edmonton";
const DISPLAY_TZ_LABEL = "Mountain Time";

// ── Helpers ──────────────────────────────────────────────────────────────────
const sha256Hex = (s: string) => createHash("sha256").update(s).digest("hex");

const escapeHtml = (s: string) =>
  s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!));

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// Verifies the activate-voucher session token; returns voucher_id or null.
const verifySession = (token: unknown, secret: string): string | null => {
  if (typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length !== 4 || parts[0] !== "v1") return null;
  const [, voucherId, expStr, sig] = parts;
  if (!UUID_RE.test(voucherId) || !/^\d+$/.test(expStr) || !/^[0-9a-f]{64}$/.test(sig)) return null;
  const expected = createHmac("sha256", secret).update(`v1.${voucherId}.${expStr}`).digest();
  const given = Buffer.from(sig, "hex");
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) return null;
  if (Number(expStr) * 1000 <= Date.now()) return null;
  return voucherId.toLowerCase();
};

type Slot = { start: string; end: string };
const parseSlots = (raw: unknown): { slots: Slot[] } | { errors: string[] } => {
  const errors: string[] = [];
  if (!Array.isArray(raw) || raw.length < MIN_SLOTS || raw.length > MAX_SLOTS) {
    return { errors: [`slots must be an array of ${MIN_SLOTS}-${MAX_SLOTS} items`] };
  }
  const now = Date.now();
  const slots: Slot[] = [];
  raw.forEach((s, i) => {
    const start = typeof s?.start === "string" ? Date.parse(s.start) : NaN;
    const end = typeof s?.end === "string" ? Date.parse(s.end) : NaN;
    if (Number.isNaN(start) || Number.isNaN(end)) return errors.push(`slots[${i}]: start/end must be ISO timestamps`);
    if (end <= start) return errors.push(`slots[${i}]: end must be after start`);
    if (end - start > MAX_SLOT_DURATION_MS) return errors.push(`slots[${i}]: longer than 24h`);
    if (start < now + MIN_LEAD_MS) return errors.push(`slots[${i}]: must start at least 24h from now`);
    if (start > now + MAX_HORIZON_MS) return errors.push(`slots[${i}]: more than a year ahead`);
    slots.push({ start: new Date(start).toISOString(), end: new Date(end).toISOString() });
  });
  if (new Set(slots.map((s) => s.start)).size !== slots.length) errors.push("slots must not repeat");
  return errors.length ? { errors } : { slots };
};

const fmtSlot = (s: Slot) => {
  const day = new Intl.DateTimeFormat("en-CA", { dateStyle: "full", timeStyle: "short", timeZone: DISPLAY_TZ });
  const end = new Intl.DateTimeFormat("en-CA", { timeStyle: "short", timeZone: DISPLAY_TZ });
  return `${day.format(new Date(s.start))} – ${end.format(new Date(s.end))} (${DISPLAY_TZ_LABEL})`;
};

Deno.serve(async (req) => {
  const appBaseUrl = (Deno.env.get("APP_BASE_URL") ?? "").replace(/\/+$/, "");
  const cors = {
    "Access-Control-Allow-Origin": appBaseUrl,
    "Access-Control-Allow-Headers": "content-type",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Vary": "Origin",
  };
  const json = (status: number, body: unknown, extra: Record<string, string> = {}) =>
    new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json", ...cors, ...extra },
    });

  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
  if (req.method !== "POST") return json(405, { error: "method_not_allowed" });

  try {
    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    const sessionSecret = Deno.env.get("SESSION_SIGNING_SECRET");
    const resendKey = Deno.env.get("RESEND_API_KEY");
    if (!supabaseUrl || !serviceKey || !sessionSecret || !resendKey || !appBaseUrl) {
      return json(500, { error: "server_misconfigured" });
    }
    const fromAddress = Deno.env.get("RESEND_FROM") || DEFAULT_FROM;
    const admin = createClient(supabaseUrl, serviceKey);

    // 1 · Session (authenticates the recipient; voucher_id comes from here).
    const body = await req.json().catch(() => ({} as Record<string, unknown>));
    const voucherId = verifySession(body?.session_token, sessionSecret);
    if (!voucherId) return json(401, { error: "session_expired" });

    // 2 · Input shape.
    const parsed = parseSlots(body?.slots);
    if ("errors" in parsed) return json(400, { error: "invalid_input", details: parsed.errors });
    const partySize = body?.party_size === undefined ? 1 : Number(body.party_size);
    if (!Number.isInteger(partySize) || partySize < PARTY_MIN || partySize > PARTY_MAX) {
      return json(400, { error: "invalid_input", details: [`party_size must be ${PARTY_MIN}-${PARTY_MAX}`] });
    }

    // 3 · Voucher → experience → provider bookability chain.
    const { data: voucher, error: vErr } = await admin
      .from("vouchers")
      .select("id, status, pinned_experience_id, pin_expires_at")
      .eq("id", voucherId)
      .maybeSingle();
    if (vErr) return json(500, { error: "server_error" });
    if (!voucher) return json(404, { error: "not_found" });

    if (!["activated", "partially_used"].includes(voucher.status)) {
      return json(409, { error: "not_bookable", reason: "voucher_not_active" });
    }
    if (!voucher.pinned_experience_id) {
      return json(409, { error: "not_bookable", reason: "no_pinned_experience" });
    }
    // pin_expires_at may be in the past here: the pin→open-balance conversion
    // job does not exist yet, so a still-pinned experience stays bookable.
    // Deliberate, known Phase 1 edge — not a bug. Revisit with the job.

    const { data: experience, error: eErr } = await admin
      .from("experiences")
      .select("id, title, slug, retail_price_cents, currency, status, provider:providers(id, name, slug, status, booking_mode, contact_email)")
      .eq("id", voucher.pinned_experience_id)
      .maybeSingle();
    if (eErr) return json(500, { error: "server_error" });
    const provider = experience?.provider as
      | { id: string; name: string; slug: string; status: string; booking_mode: string; contact_email: string | null }
      | null;
    if (!experience || experience.status !== "active") {
      return json(409, { error: "not_bookable", reason: "experience_not_active" });
    }
    if (!provider || provider.status !== "active" || !provider.contact_email) {
      return json(409, { error: "not_bookable", reason: "provider_not_active" });
    }
    if (provider.booking_mode !== "request") {
      return json(409, { error: "not_bookable", reason: "provider_not_request_mode" });
    }

    // 4 · Existing bookings: one live booking per voucher in Phase 1.
    const { data: existing, error: bErr } = await admin
      .from("bookings")
      .select("id, status, party_size, amount_cents")
      .eq("voucher_id", voucherId)
      .in("status", ["pending_provider", "hold", "confirmed"]);
    if (bErr) return json(500, { error: "server_error" });
    if (existing?.some((b) => b.status === "hold" || b.status === "confirmed")) {
      return json(409, { error: "already_booked" });
    }
    const pendingBooking = existing?.find((b) => b.status === "pending_provider") ?? null;

    // 5 · Email rate limits (spam protection), counted via audit events.
    const countEmails = async (byVoucher: boolean, windowMs: number) => {
      let q = admin.from("events")
        .select("id", { count: "exact", head: true })
        .eq("event", "booking_request.email_sent")
        .gte("created_at", new Date(Date.now() - windowMs).toISOString());
      if (byVoucher) q = q.eq("entity_type", "voucher").eq("entity_id", voucherId);
      const { count, error } = await q;
      if (error) throw new Error(`rate limit query failed: ${error.message}`);
      return count ?? 0;
    };

    const sendMagicLink = async (requestId: string, token: string, slots: Slot[], party: number) => {
      const respondUrl = `${appBaseUrl}/provider/respond/${token}`;
      const slotItems = slots.map((s) => `<li style="margin:0 0 8px 0;line-height:1.5">${escapeHtml(fmtSlot(s))}</li>`).join("");
      const html = `<!doctype html><html><body style="margin:0;background:#f7f5fb;font-family:'Poppins',Arial,sans-serif;color:#1a1a1a">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f7f5fb;padding:32px 0">
    <tr><td align="center">
      <table role="presentation" width="560" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:14px;padding:32px 36px;box-shadow:0 2px 8px rgba(60,17,174,0.08)">
        <tr><td>
          <div style="font-weight:700;font-size:24px;color:#3C11AE;letter-spacing:-0.5px;margin-bottom:18px">Turile</div>
          <h1 style="font-size:18px;color:#3C11AE;margin:0 0 14px 0;font-weight:600">New booking request</h1>
          <p style="margin:0 0 12px 0;line-height:1.55">Hi ${escapeHtml(provider.name)},</p>
          <p style="margin:0 0 12px 0;line-height:1.55">A Turile gift recipient would like to book <strong>${escapeHtml(experience.title)}</strong> for <strong>${party} ${party === 1 ? "person" : "people"}</strong>. They proposed the following times:</p>
          <ul style="margin:0 0 12px 0;padding-left:20px">${slotItems}</ul>
          <p style="margin:24px 0;text-align:center">
            <a href="${respondUrl}" style="display:inline-block;background:#3C11AE;color:#fff;text-decoration:none;font-weight:600;padding:12px 22px;border-radius:8px">Confirm or propose another time</a>
          </p>
          <p style="margin:0 0 8px 0;line-height:1.55;font-size:13px;color:#666">Or copy this link:<br><a href="${respondUrl}" style="color:#3C11AE;word-break:break-all">${escapeHtml(respondUrl)}</a></p>
          <p style="margin:12px 0 0 0;font-size:12px;color:#888">This link is personal and expires in 7 days. Please respond within 48 hours.</p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body></html>`;

      const res = await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${resendKey}` },
        body: JSON.stringify({
          from: fromAddress,
          to: [provider.contact_email],
          subject: `Booking request: ${experience.title}`,
          html,
        }),
      });

      if (!res.ok) {
        const errText = await res.text().catch(() => "");
        const errMsg = `Resend ${res.status}: ${errText.slice(0, 500)}`;
        await admin.from("booking_requests").update({ email_error: errMsg, email_to: provider.contact_email }).eq("id", requestId);
        await admin.from("events").insert({
          entity_type: "voucher", entity_id: voucherId, event: "booking_request.email_failed",
          actor: "system", payload: { request_id: requestId, status: res.status },
        });
        return false;
      }
      await admin.from("booking_requests").update({
        email_sent_at: new Date().toISOString(), email_to: provider.contact_email, email_error: null,
      }).eq("id", requestId);
      await admin.from("events").insert({
        entity_type: "voucher", entity_id: voucherId, event: "booking_request.email_sent",
        actor: "system", payload: { request_id: requestId },
      });
      return true;
    };

    const requestSummary = (r: { id: string; proposed_slots: unknown; token_expires_at: string; email_sent_at: string | null }) => ({
      id: r.id,
      proposed_slots: r.proposed_slots,
      token_expires_at: r.token_expires_at,
      email_sent_at: r.email_sent_at,
    });

    // 6a · Idempotent repeat: pending booking exists → no duplicates; retry
    //      the email only if the previous send failed.
    if (pendingBooking) {
      const { data: request, error: rErr } = await admin
        .from("booking_requests")
        .select("id, proposed_slots, token_expires_at, email_sent_at, email_error")
        .eq("booking_id", pendingBooking.id)
        .eq("provider_response", "pending")
        .maybeSingle();
      if (rErr || !request) return json(500, { error: "server_error" });

      if (request.email_sent_at && !request.email_error) {
        return json(200, {
          ok: true, already_pending: true,
          booking: { id: pendingBooking.id, status: "pending_provider", party_size: pendingBooking.party_size, amount_cents: pendingBooking.amount_cents },
          request: requestSummary(request),
        });
      }

      // Previous send failed → mint a fresh token (plaintext of the old one
      // is gone by design), update hash+expiry, resend.
      const [perVoucher, global] = await Promise.all([
        countEmails(true, 24 * 60 * 60 * 1000),
        countEmails(false, 60 * 60 * 1000),
      ]);
      if (perVoucher >= EMAILS_PER_VOUCHER_24H || global >= EMAILS_GLOBAL_1H) {
        return json(429, { error: "too_many_requests" }, { "Retry-After": String(RETRY_AFTER_S) });
      }
      const token = randomBytes(32).toString("base64url");
      const expiresAt = new Date(Date.now() + PROVIDER_TOKEN_TTL_MS).toISOString();
      const { error: uErr } = await admin
        .from("booking_requests")
        .update({ provider_token_hash: sha256Hex(token), token_expires_at: expiresAt })
        .eq("id", request.id);
      if (uErr) return json(500, { error: "server_error" });

      const sent = await sendMagicLink(request.id, token, request.proposed_slots as Slot[], pendingBooking.party_size);
      if (!sent) return json(502, { error: "email_failed" });
      return json(200, {
        ok: true, already_pending: true, resent: true,
        booking: { id: pendingBooking.id, status: "pending_provider", party_size: pendingBooking.party_size, amount_cents: pendingBooking.amount_cents },
        request: requestSummary({ ...request, token_expires_at: expiresAt, email_sent_at: new Date().toISOString() }),
      });
    }

    // 6b · Fresh creation.
    const [perVoucher, global] = await Promise.all([
      countEmails(true, 24 * 60 * 60 * 1000),
      countEmails(false, 60 * 60 * 1000),
    ]);
    if (perVoucher >= EMAILS_PER_VOUCHER_24H || global >= EMAILS_GLOBAL_1H) {
      return json(429, { error: "too_many_requests" }, { "Retry-After": String(RETRY_AFTER_S) });
    }

    const token = randomBytes(32).toString("base64url");
    const expiresAt = new Date(Date.now() + PROVIDER_TOKEN_TTL_MS).toISOString();
    const { data: created, error: cErr } = await admin.rpc("create_booking_request", {
      p_voucher_id: voucherId,
      p_experience_id: experience.id,
      p_provider_id: provider.id,
      p_amount_cents: experience.retail_price_cents, // snapshot; money moves only at confirm (spec §4 ordering rule)
      p_party_size: partySize,
      p_proposed_slots: parsed.slots,
      p_token_hash: sha256Hex(token),
      p_token_expires_at: expiresAt,
    });
    if (cErr) return json(500, { error: "server_error" });
    const { booking_id, request_id } = created as { booking_id: string; request_id: string };

    const sent = await sendMagicLink(request_id, token, parsed.slots, partySize);
    if (!sent) return json(502, { error: "email_failed" }); // state kept; repeat call retries the send

    return json(200, {
      ok: true,
      booking: { id: booking_id, status: "pending_provider", party_size: partySize, amount_cents: experience.retail_price_cents },
      request: { id: request_id, proposed_slots: parsed.slots, token_expires_at: expiresAt, email_sent_at: new Date().toISOString() },
    });
  } catch (e) {
    console.error("booking-request error:", e instanceof Error ? e.message : e);
    return json(500, { error: "server_error" });
  }
});
