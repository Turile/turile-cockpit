// Provider magic-link endpoint (verify_jwt = false in config.toml).
// Target of ${APP_BASE_URL}/provider/respond/<token> from booking-request emails.
//
//   POST { token, action: "verify" }                          -> 200 booking summary
//   POST { token, action: "accept", slot_index }              -> 200 confirmed (REDEEMS the gift card)
//   POST { token, action: "propose_alternative", slot, note? }-> 200 (booking failed, recipient re-books)
//   POST { token, action: "decline", note? }                  -> 200 (booking failed, voucher untouched)
//
// Auth: provider-side, separate from the recipient session_token. The URL
// token is hashed (SHA-256) and looked up by provider_token_hash; invalid,
// expired and already-burned tokens all get one 404 body.
//
// Accept is the FIRST place money moves (spec §4 ordering rule), done as a
// 3-step saga because a Shopify call cannot live inside a DB transaction:
//   A. atomic claim  — conditional UPDATE pending→accepted; a double click /
//      second tab loses the race and never reaches the redeem step.
//   B. redeem        — live balance check, then giftCardDebit. Any failure
//      compensates the claim back to pending (token stays valid, provider
//      can retry); nothing is confirmed without captured money.
//   C. finalize      — one DB transaction (RPC): booking confirmed, one-shot
//      token burned, voucher status updated, redeemed+confirmed events.
// Known reconciliation edge: a crash between B and C leaves money captured
// with the booking still pending. The voucher.redeem_started/redeemed event
// pair makes such cases visible; the claim guard prevents double debits.
//
// No rate limiting here by design: the token carries 256 bits of entropy
// (guessing is infeasible) and nothing is sent/mutated without a valid one.

import { createClient } from "https://esm.sh/@supabase/supabase-js@2.45.0";
import { createHash } from "node:crypto";

const MAX_NOTE_LEN = 500;
const ALT_MIN_LEAD_MS = 24 * 60 * 60 * 1000;
const ALT_MAX_HORIZON_MS = 365 * 24 * 60 * 60 * 1000;
const ALT_MAX_DURATION_MS = 24 * 60 * 60 * 1000;
const DEFAULT_FROM = "Turile <bookings@turil.ca>"; // override via RESEND_FROM secret
const SHOPIFY_API_VERSION = "2025-07";
// TODO(phase2): per-provider timezone; Alberta-first for now.
const DISPLAY_TZ = "America/Edmonton";
const DISPLAY_TZ_LABEL = "Mountain Time";

const INVALID_BODY = { error: "invalid_or_expired", message: "Це посилання недійсне або вже використане" };

const sha256Hex = (s: string) => createHash("sha256").update(s).digest("hex");
const escapeHtml = (s: string) =>
  s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!));

type Slot = { start: string; end: string };
const fmtSlot = (s: Slot) => {
  const day = new Intl.DateTimeFormat("en-CA", { dateStyle: "full", timeStyle: "short", timeZone: DISPLAY_TZ });
  const end = new Intl.DateTimeFormat("en-CA", { timeStyle: "short", timeZone: DISPLAY_TZ });
  return `${day.format(new Date(s.start))} – ${end.format(new Date(s.end))} (${DISPLAY_TZ_LABEL})`;
};

const centsToAmount = (cents: number) => (cents / 100).toFixed(2);

Deno.serve(async (req) => {
  const appBaseUrl = (Deno.env.get("APP_BASE_URL") ?? "").replace(/\/+$/, "");
  const cors = {
    "Access-Control-Allow-Origin": appBaseUrl,
    "Access-Control-Allow-Headers": "content-type",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Vary": "Origin",
  };
  const json = (status: number, body: unknown) =>
    new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json", ...cors },
    });

  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
  if (req.method !== "POST") return json(405, { error: "method_not_allowed" });

  try {
    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    const shopifyClientId = Deno.env.get("SHOPIFY_CLIENT_ID");
    const shopifyClientSecret = Deno.env.get("SHOPIFY_CLIENT_SECRET");
    const shopifyDomain = Deno.env.get("SHOPIFY_STORE_DOMAIN");
    const resendKey = Deno.env.get("RESEND_API_KEY");
    if (!supabaseUrl || !serviceKey || !shopifyClientId || !shopifyClientSecret || !shopifyDomain || !resendKey || !appBaseUrl) {
      return json(500, { error: "server_misconfigured" });
    }
    const fromAddress = Deno.env.get("RESEND_FROM") || DEFAULT_FROM;
    const admin = createClient(supabaseUrl, serviceKey);

    const body = await req.json().catch(() => ({} as Record<string, unknown>));
    const action = typeof body?.action === "string" ? body.action : "";
    const token = typeof body?.token === "string" ? body.token.trim() : "";
    if (!["verify", "accept", "propose_alternative", "decline"].includes(action)) {
      return json(400, { error: "invalid_input", details: ["unknown action"] });
    }
    if (!/^[A-Za-z0-9_\-]{20,80}$/.test(token)) return json(404, INVALID_BODY);

    // ── Token → request → booking chain ─────────────────────────────────────
    const { data: request, error: rErr } = await admin
      .from("booking_requests")
      .select("id, booking_id, proposed_slots, token_expires_at, provider_response")
      .eq("provider_token_hash", sha256Hex(token))
      .maybeSingle();
    if (rErr) return json(500, { error: "server_error" });
    if (!request || request.provider_response !== "pending" ||
        new Date(request.token_expires_at).getTime() <= Date.now()) {
      return json(404, INVALID_BODY);
    }

    const { data: booking, error: bErr } = await admin
      .from("bookings")
      .select("id, voucher_id, experience_id, provider_id, party_size, amount_cents, status")
      .eq("id", request.booking_id)
      .maybeSingle();
    if (bErr || !booking) return json(500, { error: "server_error" });
    if (booking.status !== "pending_provider") return json(404, INVALID_BODY);

    const [{ data: experience }, { data: provider }, { data: voucher }] = await Promise.all([
      admin.from("experiences").select("title, slug").eq("id", booking.experience_id).maybeSingle(),
      admin.from("providers").select("name").eq("id", booking.provider_id).maybeSingle(),
      admin.from("vouchers").select("id, shopify_gift_card_id, recipient_email, purchaser_email").eq("id", booking.voucher_id).maybeSingle(),
    ]);
    if (!experience || !provider || !voucher) return json(500, { error: "server_error" });
    const slots = request.proposed_slots as Slot[];

    // ── verify (read-only, token not burned) ────────────────────────────────
    if (action === "verify") {
      return json(200, {
        ok: true,
        experience_title: experience.title,
        provider_name: provider.name,
        party_size: booking.party_size,
        proposed_slots: slots,
        token_expires_at: request.token_expires_at,
      });
    }

    // Recipient notification — after state is committed; failure never
    // affects the outcome, only leaves an audit event.
    const notifyRecipient = async (subject: string, heading: string, bodyHtml: string) => {
      const to = voucher.recipient_email ?? voucher.purchaser_email;
      if (!to) return;
      const html = `<!doctype html><html><body style="margin:0;background:#f7f5fb;font-family:'Poppins',Arial,sans-serif;color:#1a1a1a">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f7f5fb;padding:32px 0">
    <tr><td align="center">
      <table role="presentation" width="560" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:14px;padding:32px 36px;box-shadow:0 2px 8px rgba(60,17,174,0.08)">
        <tr><td>
          <div style="font-weight:700;font-size:24px;color:#3C11AE;letter-spacing:-0.5px;margin-bottom:18px">Turile</div>
          <h1 style="font-size:18px;color:#3C11AE;margin:0 0 14px 0;font-weight:600">${escapeHtml(heading)}</h1>
          ${bodyHtml}
        </td></tr>
      </table>
    </td></tr>
  </table>
</body></html>`;
      const res = await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${resendKey}` },
        body: JSON.stringify({ from: fromAddress, to: [to], subject, html }),
      });
      if (!res.ok) {
        await admin.from("events").insert({
          entity_type: "booking", entity_id: booking.id, event: "booking.notify_failed",
          actor: "system", payload: { request_id: request.id, status: res.status },
        });
      }
    };

    // ── decline / propose_alternative (no money involved) ───────────────────
    if (action === "decline" || action === "propose_alternative") {
      const note = typeof body?.note === "string" ? body.note.trim().slice(0, MAX_NOTE_LEN) : null;
      let altSlot: Slot | null = null;
      if (action === "propose_alternative") {
        const s = body?.slot as Record<string, unknown> | undefined;
        const start = typeof s?.start === "string" ? Date.parse(s.start) : NaN;
        const end = typeof s?.end === "string" ? Date.parse(s.end) : NaN;
        const now = Date.now();
        if (Number.isNaN(start) || Number.isNaN(end) || end <= start ||
            end - start > ALT_MAX_DURATION_MS || start < now + ALT_MIN_LEAD_MS || start > now + ALT_MAX_HORIZON_MS) {
          return json(400, { error: "invalid_input", details: ["slot must be a valid future {start,end} pair"] });
        }
        altSlot = { start: new Date(start).toISOString(), end: new Date(end).toISOString() };
      }

      const response = action === "decline" ? "declined" : "alternative_proposed";
      const { data: done, error: fErr } = await admin.rpc("finalize_booking_response", {
        p_request_id: request.id,
        p_booking_id: booking.id,
        p_response: response,
        p_event_payload: {
          reason: response,
          request_id: request.id,
          voucher_id: voucher.id,
          ...(altSlot ? { alternative_slot: altSlot } : {}),
          ...(note ? { note } : {}),
        },
      });
      if (fErr) return json(500, { error: "server_error" });
      if (!done) return json(404, INVALID_BODY); // lost the race / already responded

      if (action === "decline") {
        await notifyRecipient(
          `Update on your booking: ${experience.title}`,
          "The provider can't make these times",
          `<p style="margin:0 0 12px 0;line-height:1.55">${escapeHtml(provider.name)} wasn't able to confirm any of your proposed times for <strong>${escapeHtml(experience.title)}</strong>.${note ? ` Their note: “${escapeHtml(note)}”` : ""}</p>
           <p style="margin:0 0 12px 0;line-height:1.55">Your voucher was not charged. You can propose new times or exchange for another experience anytime:</p>
           <p style="margin:24px 0;text-align:center"><a href="${appBaseUrl}" style="display:inline-block;background:#3C11AE;color:#fff;text-decoration:none;font-weight:600;padding:12px 22px;border-radius:8px">Open my voucher</a></p>`,
        );
      } else {
        await notifyRecipient(
          `New time suggested: ${experience.title}`,
          "The provider suggested another time",
          `<p style="margin:0 0 12px 0;line-height:1.55">${escapeHtml(provider.name)} can't make your proposed times for <strong>${escapeHtml(experience.title)}</strong>, but suggested:</p>
           <p style="margin:0 0 12px 0;line-height:1.55;font-weight:600">${escapeHtml(fmtSlot(altSlot!))}</p>
           ${note ? `<p style="margin:0 0 12px 0;line-height:1.55">Note: “${escapeHtml(note)}”</p>` : ""}
           <p style="margin:0 0 12px 0;line-height:1.55">Your voucher was not charged. If this works for you, simply book again with this time:</p>
           <p style="margin:24px 0;text-align:center"><a href="${appBaseUrl}" style="display:inline-block;background:#3C11AE;color:#fff;text-decoration:none;font-weight:600;padding:12px 22px;border-radius:8px">Book again</a></p>`,
        );
      }
      return json(200, { ok: true, response });
    }

    // ── accept: the 3-step saga ──────────────────────────────────────────────
    const slotIndex = Number(body?.slot_index);
    if (!Number.isInteger(slotIndex) || slotIndex < 0 || slotIndex >= slots.length) {
      return json(400, { error: "invalid_input", details: [`slot_index must be 0-${slots.length - 1}`] });
    }
    const accepted = slots[slotIndex];

    // A · Atomic claim — exactly one caller proceeds to the redeem step.
    const { data: claimed, error: clErr } = await admin
      .from("booking_requests")
      .update({ provider_response: "accepted", accepted_slot: accepted, responded_at: new Date().toISOString() })
      .eq("id", request.id)
      .eq("provider_response", "pending")
      .select("id");
    if (clErr) return json(500, { error: "server_error" });
    if (!claimed?.length) return json(404, INVALID_BODY); // second tab / double click

    const compensate = () =>
      admin.from("booking_requests")
        .update({ provider_response: "pending", accepted_slot: null, responded_at: null })
        .eq("id", request.id);

    await admin.from("events").insert({
      entity_type: "voucher", entity_id: voucher.id, event: "voucher.redeem_started",
      actor: "provider", payload: { booking_id: booking.id, request_id: request.id, amount_cents: booking.amount_cents },
    });

    // B · Redeem against Shopify (money source of truth).
    let balanceAfterCents: number, transactionGid: string, currency: string;
    try {
      const tokenRes = await fetch(`https://${shopifyDomain}/admin/oauth/access_token`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ grant_type: "client_credentials", client_id: shopifyClientId, client_secret: shopifyClientSecret }),
      });
      if (!tokenRes.ok) throw new Error(`token exchange ${tokenRes.status}`);
      const { access_token } = await tokenRes.json();
      const gql = async (query: string, variables: Record<string, unknown>) => {
        const res = await fetch(`https://${shopifyDomain}/admin/api/${SHOPIFY_API_VERSION}/graphql.json`, {
          method: "POST",
          headers: { "Content-Type": "application/json", "X-Shopify-Access-Token": access_token },
          body: JSON.stringify({ query, variables }),
        });
        const out = await res.json();
        if (!res.ok || out.errors?.length) throw new Error(`graphql ${res.status}: ${JSON.stringify(out.errors ?? "").slice(0, 300)}`);
        return out.data;
      };
      const cardGid = `gid://shopify/GiftCard/${voucher.shopify_gift_card_id}`;

      const bal = await gql(
        `query($id: ID!) { giftCard(id: $id) { balance { amount currencyCode } deactivatedAt } }`,
        { id: cardGid },
      );
      const card = bal?.giftCard;
      if (!card || card.deactivatedAt) throw new Error("gift card unavailable");
      const balanceCents = Math.round(parseFloat(card.balance.amount) * 100);
      currency = card.balance.currencyCode;
      if (balanceCents < booking.amount_cents) {
        await compensate();
        return json(409, { error: "insufficient_balance" }); // resolved via exchange flow, not here
      }

      const debit = await gql(
        `mutation($id: ID!, $debitInput: GiftCardDebitInput!) {
           giftCardDebit(id: $id, debitInput: $debitInput) {
             giftCardDebitTransaction { id amount { amount currencyCode } giftCard { balance { amount currencyCode } } }
             userErrors { field message }
           }
         }`,
        { id: cardGid, debitInput: { debitAmount: { amount: centsToAmount(booking.amount_cents), currencyCode: currency } } },
      );
      const result = debit?.giftCardDebit;
      if (!result?.giftCardDebitTransaction || result.userErrors?.length) {
        throw new Error(`debit rejected: ${JSON.stringify(result?.userErrors ?? "").slice(0, 300)}`);
      }
      transactionGid = result.giftCardDebitTransaction.id;
      balanceAfterCents = Math.round(parseFloat(result.giftCardDebitTransaction.giftCard.balance.amount) * 100);
    } catch (e) {
      console.error("redeem failed:", e instanceof Error ? e.message : e);
      await compensate();
      await admin.from("events").insert({
        entity_type: "voucher", entity_id: voucher.id, event: "voucher.redeem_failed",
        actor: "system", payload: { booking_id: booking.id, request_id: request.id },
      });
      return json(502, { error: "redeem_failed" }); // token still valid — provider can retry
    }

    // C · Finalize in one DB transaction; burns the one-shot token.
    const { error: finErr } = await admin.rpc("finalize_booking_acceptance", {
      p_request_id: request.id,
      p_booking_id: booking.id,
      p_voucher_id: voucher.id,
      p_slot_start: accepted.start,
      p_slot_end: accepted.end,
      p_voucher_status: balanceAfterCents === 0 ? "depleted" : "partially_used",
      p_redeem_payload: {
        booking_id: booking.id,
        request_id: request.id,
        amount_cents: booking.amount_cents,
        transaction_gid: transactionGid,
        balance_after_cents: balanceAfterCents,
      },
    });
    if (finErr) {
      // Money IS captured; do NOT compensate the claim (that would re-open the
      // door to a second debit). This is the named reconciliation edge — the
      // redeem_started/redeemed trail plus this event make it findable.
      console.error("finalize failed after successful debit:", finErr.message);
      await admin.from("events").insert({
        entity_type: "booking", entity_id: booking.id, event: "booking.finalize_failed",
        actor: "system", payload: { request_id: request.id, transaction_gid: transactionGid },
      });
      return json(500, { error: "server_error" });
    }

    await notifyRecipient(
      `Your booking is confirmed: ${experience.title}`,
      "You're booked!",
      `<p style="margin:0 0 12px 0;line-height:1.55">${escapeHtml(provider.name)} confirmed your booking of <strong>${escapeHtml(experience.title)}</strong> for ${booking.party_size} ${booking.party_size === 1 ? "person" : "people"}:</p>
       <p style="margin:0 0 12px 0;line-height:1.55;font-weight:600">${escapeHtml(fmtSlot(accepted))}</p>
       <p style="margin:0 0 12px 0;line-height:1.55;font-size:13px;color:#666">Booking reference: ${booking.id}</p>`,
    );

    return json(200, {
      ok: true,
      response: "accepted",
      booking: { id: booking.id, status: "confirmed", slot: accepted, party_size: booking.party_size },
    });
  } catch (e) {
    console.error("provider-respond error:", e instanceof Error ? e.message : e);
    return json(500, { error: "server_error" });
  }
});
