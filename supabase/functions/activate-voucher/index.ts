// Public voucher-activation endpoint (verify_jwt = false in config.toml).
//
//   POST { code, email, pin } -> 200 { ok, voucher } | 400 | 404 | 429 | 503
//
// Security model (see spec §5.1 and the approved v2 proposal):
// - Codes are semi-guessable → per-IP + global sliding-window rate limits
//   (activation_attempts) run BEFORE any vouchers access.
// - "code not found", "email mismatch", "PIN wrong" and "no PIN issued" are
//   externally indistinguishable: one 404 body, one combined email+PIN
//   verdict, scrypt executed on every path (dummy when no voucher).
// - Per-voucher tarpit: after FREE_FAILS failed attempts the response is
//   delayed (capped), never hard-locked and never a distinct status — a
//   lock or a special error would be a code-existence oracle / DoS lever.
// - Balance is read live from Shopify (source of monetary truth), never
//   from our DB. Secrets come from Deno.env only and are never logged.

import { createClient } from "https://esm.sh/@supabase/supabase-js@2.45.0";
import { createHash, scrypt as scryptCb, timingSafeEqual } from "node:crypto";
import { Buffer } from "node:buffer";

// ── Tunables ─────────────────────────────────────────────────────────────────
const IP_WINDOW_SHORT_MS = 10 * 60 * 1000; //  5 attempts / 10 min / IP
const IP_LIMIT_SHORT = 5;
const IP_WINDOW_DAY_MS = 24 * 60 * 60 * 1000; // 30 attempts / 24 h / IP
const IP_LIMIT_DAY = 30;
const GLOBAL_WINDOW_MS = 60 * 60 * 1000; // 300 attempts / hour, all IPs
const GLOBAL_LIMIT = 300;
const RETRY_AFTER_S = 600;

const FREE_FAILS = 3; // tarpit: 1s, 2s, 4s, 8s, 8s, ... after this many fails
const TARPIT_CAP_MS = 8000;

const SCRYPT_N = 16384, SCRYPT_R = 8, SCRYPT_P = 1, SCRYPT_LEN = 32;
const PIN_HASH_VERSION = "v1";
// Burned on every no-voucher path so "code not found" costs the same as a PIN check.
const DUMMY_SALT = "0000000000000000000000000000000000000000000000000000000000000000";

const NOT_FOUND_BODY = {
  error: "not_found",
  message: "Це поєднання коду, email та PIN не знайдено",
};

// ── Helpers ──────────────────────────────────────────────────────────────────
const EMAIL_RE = /^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$/;
const cleanEmail = (v: unknown): string | null => {
  if (typeof v !== "string") return null;
  const s = v.normalize("NFKC").replace(/[\u200B-\u200D\uFEFF\u00A0]/g, "").trim();
  return /^[\x20-\x7E]+$/.test(s) && EMAIL_RE.test(s) ? s.toLowerCase() : null;
};

const normalizeCode = (v: unknown): string | null => {
  if (typeof v !== "string") return null;
  const s = v.toUpperCase().replace(/[\s\-]/g, "");
  return /^[A-Z0-9]{6,64}$/.test(s) ? s : null;
};

const sha256Hex = (s: string) => createHash("sha256").update(s).digest("hex");

const scrypt = (pin: string, saltHex: string): Promise<Buffer> =>
  new Promise((resolve, reject) =>
    scryptCb(pin, Buffer.from(saltHex, "hex"), SCRYPT_LEN,
      { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P },
      (err, key) => err ? reject(err) : resolve(key as Buffer)));

const verifyPin = async (pin: string, saltHex: string, storedHash: string): Promise<boolean> => {
  const derived = await scrypt(pin, saltHex);
  const parts = storedHash.split("$");
  if (parts.length !== 2 || parts[0] !== PIN_HASH_VERSION) return false;
  const stored = Buffer.from(parts[1], "hex");
  if (stored.length !== derived.length) return false;
  return timingSafeEqual(derived, stored);
};

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

Deno.serve(async (req) => {
  const appBaseUrl = Deno.env.get("APP_BASE_URL") ?? "";
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
    const shopifyClientId = Deno.env.get("SHOPIFY_CLIENT_ID");
    const shopifyClientSecret = Deno.env.get("SHOPIFY_CLIENT_SECRET");
    const shopifyDomain = Deno.env.get("SHOPIFY_STORE_DOMAIN");
    if (!supabaseUrl || !serviceKey || !shopifyClientId || !shopifyClientSecret || !shopifyDomain || !appBaseUrl) {
      return json(500, { error: "server_misconfigured" });
    }
    const admin = createClient(supabaseUrl, serviceKey);

    // 1 · Input validation (shape only — reveals nothing about voucher state).
    const body = await req.json().catch(() => ({} as Record<string, unknown>));
    const code = normalizeCode(body?.code);
    const email = cleanEmail(body?.email);
    const pin = typeof body?.pin === "string" && /^\d{4}$/.test(body.pin) ? body.pin : null;
    const badFields = [
      ...(code ? [] : ["code"]),
      ...(email ? [] : ["email"]),
      ...(pin ? [] : ["pin"]),
    ];
    if (badFields.length) return json(400, { error: "invalid_input", fields: badFields });

    // 2 · Rate limiting BEFORE any voucher access.
    const ip = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || "0.0.0.0";
    const now = Date.now();
    const countSince = async (sinceMs: number, byIp: boolean) => {
      let q = admin.from("activation_attempts")
        .select("id", { count: "exact", head: true })
        .gte("created_at", new Date(now - sinceMs).toISOString());
      if (byIp) q = q.eq("ip", ip);
      const { count, error } = await q;
      if (error) throw new Error(`rate limit query failed: ${error.message}`);
      return count ?? 0;
    };
    const [ipShort, ipDay, global] = await Promise.all([
      countSince(IP_WINDOW_SHORT_MS, true),
      countSince(IP_WINDOW_DAY_MS, true),
      countSince(GLOBAL_WINDOW_MS, false),
    ]);
    if (ipShort >= IP_LIMIT_SHORT || ipDay >= IP_LIMIT_DAY || global >= GLOBAL_LIMIT) {
      return json(429, { error: "too_many_attempts" }, { "Retry-After": String(RETRY_AFTER_S) });
    }

    // 3 · Record the attempt (counts even if everything below fails). No code stored.
    const { data: attempt, error: aErr } = await admin
      .from("activation_attempts")
      .insert({ ip })
      .select("id")
      .single();
    if (aErr) return json(500, { error: "server_error" });

    // 4 · Lookup by code hash.
    const { data: voucher, error: vErr } = await admin
      .from("vouchers")
      .select("id, code_last4, shopify_gift_card_id, initial_value_cents, pinned_experience_id, pin_expires_at, purchaser_email, recipient_email, status, activated_at, access_pin_hash, access_pin_salt, activation_fail_count")
      .eq("code_hash", sha256Hex(code))
      .maybeSingle();
    if (vErr) return json(500, { error: "server_error" });

    // 5 · Tarpit: escalating delay after repeated failures against this voucher.
    //     Applied before the verdict, to success and failure alike.
    if (voucher && voucher.activation_fail_count > FREE_FAILS) {
      const delay = Math.min(
        2 ** (voucher.activation_fail_count - FREE_FAILS - 1) * 1000,
        TARPIT_CAP_MS,
      );
      await sleep(delay);
    }

    // 6 · Single combined verdict. scrypt runs on EVERY path; email and PIN
    //     are always both evaluated — no early exit, no per-check signal.
    let emailOk = false;
    let pinOk = false;
    if (voucher) {
      const expected = (voucher.recipient_email ?? voucher.purchaser_email ?? "").toLowerCase();
      emailOk = expected !== "" && expected === email;
      if (voucher.access_pin_hash && voucher.access_pin_salt) {
        pinOk = await verifyPin(pin, voucher.access_pin_salt, voucher.access_pin_hash);
      } else {
        await scrypt(pin, DUMMY_SALT); // no PIN issued → fail closed, same cost
      }
    } else {
      await scrypt(pin, DUMMY_SALT); // no voucher → same cost as a real check
    }

    if (!voucher || !emailOk || !pinOk) {
      if (voucher) await admin.rpc("record_voucher_activation_failure", { p_voucher_id: voucher.id });
      return json(404, NOT_FOUND_BODY);
    }

    // 7 · Credentials matched — mark the attempt successful even if Shopify
    //     is down, so legitimate retries aren't throttled as brute force.
    await admin.from("activation_attempts").update({ succeeded: true }).eq("id", attempt.id);

    // 8 · Live balance from Shopify (monetary source of truth).
    let balanceCents: number, currency: string;
    try {
      const tokenRes = await fetch(`https://${shopifyDomain}/admin/oauth/access_token`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          grant_type: "client_credentials",
          client_id: shopifyClientId,
          client_secret: shopifyClientSecret,
        }),
      });
      if (!tokenRes.ok) throw new Error(`token exchange ${tokenRes.status}`);
      const { access_token } = await tokenRes.json();

      const gqlRes = await fetch(`https://${shopifyDomain}/admin/api/2025-07/graphql.json`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Shopify-Access-Token": access_token },
        body: JSON.stringify({
          query: `query($id: ID!) { giftCard(id: $id) { balance { amount currencyCode } deactivatedAt } }`,
          variables: { id: `gid://shopify/GiftCard/${voucher.shopify_gift_card_id}` },
        }),
      });
      if (!gqlRes.ok) throw new Error(`graphql ${gqlRes.status}`);
      const gql = await gqlRes.json();
      const card = gql?.data?.giftCard;
      if (!card || gql.errors?.length) throw new Error("gift card not returned");
      balanceCents = Math.round(parseFloat(card.balance.amount) * 100);
      currency = card.balance.currencyCode;
    } catch (e) {
      // Fail closed: no state change without a trustworthy balance. Detail
      // stays server-side; never leaks Shopify specifics (or secrets) out.
      console.error("shopify balance fetch failed:", e instanceof Error ? e.message : e);
      return json(503, { error: "temporarily_unavailable" });
    }

    // 9 · First successful activation mutates state; repeats are idempotent.
    let activatedAt = voucher.activated_at;
    if (!voucher.activated_at) {
      activatedAt = new Date().toISOString();
      const bindEmail = voucher.recipient_email == null;
      const { error: uErr } = await admin
        .from("vouchers")
        .update({
          activated_at: activatedAt,
          status: "activated",
          activation_fail_count: 0,
          activation_last_failed_at: null,
          ...(bindEmail ? { recipient_email: email } : {}),
        })
        .eq("id", voucher.id);
      if (uErr) return json(500, { error: "server_error" });
      await admin.from("events").insert({
        entity_type: "voucher",
        entity_id: voucher.id,
        event: "voucher.activated",
        actor: "recipient",
        payload: { bound_email: bindEmail },
      });
    } else if (voucher.activation_fail_count > 0) {
      await admin
        .from("vouchers")
        .update({ activation_fail_count: 0, activation_last_failed_at: null })
        .eq("id", voucher.id);
    }

    // 10 · Pinned experience summary (public catalog fields only).
    let pinnedExperience = null;
    if (voucher.pinned_experience_id) {
      const { data: exp } = await admin
        .from("experiences")
        .select("title, slug, retail_price_cents, currency, provider:providers(name, slug, booking_mode)")
        .eq("id", voucher.pinned_experience_id)
        .maybeSingle();
      pinnedExperience = exp ?? null;
    }

    return json(200, {
      ok: true,
      voucher: {
        code_last4: voucher.code_last4,
        status: voucher.activated_at ? voucher.status : "activated",
        activated_at: activatedAt,
        initial_value_cents: voucher.initial_value_cents,
        balance_cents: balanceCents,
        currency,
        pin_expires_at: voucher.pin_expires_at,
        pinned_experience: pinnedExperience,
      },
    });
  } catch (e) {
    console.error("activate-voucher error:", e instanceof Error ? e.message : e);
    return json(500, { error: "server_error" });
  }
});
