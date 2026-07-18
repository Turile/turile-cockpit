// Seed a REAL test gift card in Shopify + a matching voucher row, for the
// activate-voucher e2e test. Run locally with Node >= 20:
//
//   set -a; source ~/.config/turile/admin.env; set +a
//   SUPABASE_URL=... SUPABASE_SERVICE_ROLE_KEY=... node scripts/seed-test-voucher.mjs
//
// Prints the voucher code, PIN and test email to the console ONLY — never
// writes them to any file. All seeded rows are prefixed TEST_ so they can't
// be mistaken for real data. Idempotent-ish: reuses TEST_ provider/experience
// if they already exist; always creates a fresh gift card + voucher.

import { createHash, randomBytes, scryptSync } from "node:crypto";

// Must mirror supabase/functions/activate-voucher/index.ts exactly.
const SCRYPT_N = 16384, SCRYPT_R = 8, SCRYPT_P = 1, SCRYPT_LEN = 32;
const PIN_HASH_VERSION = "v1";
const API_VERSION = "2025-07";

const env = (k) => {
  const v = process.env[k];
  if (!v) { console.error(`Missing env: ${k}`); process.exit(1); }
  return v;
};
const SHOP = env("SHOPIFY_STORE_DOMAIN");
const CLIENT_ID = env("SHOPIFY_CLIENT_ID");
const CLIENT_SECRET = env("SHOPIFY_CLIENT_SECRET");
const SB_URL = env("SUPABASE_URL");
const SB_KEY = env("SUPABASE_SERVICE_ROLE_KEY");

const die = (msg, detail) => { console.error(msg, detail ?? ""); process.exit(1); };

// ── Shopify: client-credentials token + giftCardCreate ──────────────────────
const tokenRes = await fetch(`https://${SHOP}/admin/oauth/access_token`, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ grant_type: "client_credentials", client_id: CLIENT_ID, client_secret: CLIENT_SECRET }),
});
if (!tokenRes.ok) die("token exchange failed:", await tokenRes.text());
const { access_token } = await tokenRes.json();

const gql = async (query, variables) => {
  const res = await fetch(`https://${SHOP}/admin/api/${API_VERSION}/graphql.json`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Shopify-Access-Token": access_token },
    body: JSON.stringify({ query, variables }),
  });
  const body = await res.json();
  if (!res.ok || body.errors?.length) die("graphql failed:", JSON.stringify(body.errors ?? body));
  return body.data;
};

// Generate our own code so we can print it (Shopify only reveals a generated
// code once, at creation). 16 alphanumerics, unambiguous charset.
const CODE_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const code = Array.from(randomBytes(16), (b) => CODE_CHARS[b % CODE_CHARS.length]).join("");

const created = await gql(
  `mutation($input: GiftCardCreateInput!) {
     giftCardCreate(input: $input) {
       giftCard { id lastCharacters initialValue { amount currencyCode } }
       userErrors { field message }
     }
   }`,
  { input: { initialValue: "10.00", code, note: "TEST_ turile-cockpit e2e seed — safe to disable" } },
);
const errs = created.giftCardCreate.userErrors;
if (errs?.length) die("giftCardCreate userErrors:", JSON.stringify(errs));
const card = created.giftCardCreate.giftCard;
const giftCardId = Number(card.id.split("/").pop());
console.log(`Shopify gift card created: id=${giftCardId} last4=${card.lastCharacters} value=${card.initialValue.amount} ${card.initialValue.currencyCode}`);

// ── Supabase REST helpers (service role) ─────────────────────────────────────
const sb = async (method, path, body, headers = {}) => {
  const res = await fetch(`${SB_URL}/rest/v1/${path}`, {
    method,
    headers: {
      apikey: SB_KEY,
      Authorization: `Bearer ${SB_KEY}`,
      "Content-Type": "application/json",
      Prefer: "return=representation",
      ...headers,
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => null);
  if (!res.ok) die(`supabase ${method} ${path} failed:`, JSON.stringify(data));
  return data;
};

// ── TEST_ provider + experience (reuse if present) ───────────────────────────
let [provider] = await sb("GET", "providers?slug=eq.test-provider&select=id");
if (!provider) {
  [provider] = await sb("POST", "providers", {
    name: "TEST_Provider",
    slug: "test-provider",
    booking_mode: "request",
    contact_email: "test-provider@example.com",
    status: "draft",
  });
  console.log(`Created TEST_Provider ${provider.id}`);
}
let [experience] = await sb("GET", "experiences?slug=eq.test-experience&select=id");
if (!experience) {
  [experience] = await sb("POST", "experiences", {
    provider_id: provider.id,
    title: "TEST_Experience — Hot Air Balloon (seeded)",
    slug: "test-experience",
    retail_price_cents: 1000,
    status: "draft", // draft: never exposed via the public active-only policy
  });
  console.log(`Created TEST_Experience ${experience.id}`);
}

// ── Voucher row: same hashing as the edge function ───────────────────────────
const pin = String(Math.floor(Math.random() * 10000)).padStart(4, "0");
const salt = randomBytes(16).toString("hex");
const pinHash = `${PIN_HASH_VERSION}$` +
  scryptSync(pin, Buffer.from(salt, "hex"), SCRYPT_LEN, { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P }).toString("hex");
const purchasedAt = new Date();
const pinExpiresAt = new Date(purchasedAt);
pinExpiresAt.setMonth(pinExpiresAt.getMonth() + 12);
const testEmail = "TEST_recipient@example.com".toLowerCase();

const [voucher] = await sb("POST", "vouchers", {
  code_hash: createHash("sha256").update(code).digest("hex"),
  code_last4: code.slice(-4),
  shopify_gift_card_id: giftCardId,
  shopify_order_id: 0, // TEST_: no real purchase order behind this voucher
  initial_value_cents: 1000,
  pinned_experience_id: experience.id,
  purchased_at: purchasedAt.toISOString(),
  pin_expires_at: pinExpiresAt.toISOString(),
  purchaser_email: testEmail,
  recipient_email: null, // exercise bind-on-activation
  access_pin_salt: salt,
  access_pin_hash: pinHash,
  status: "issued",
});
console.log(`Voucher row created: ${voucher.id}`);

console.log("\n=== TEST CREDENTIALS (console only — do not store) ===");
console.log(`  code:  ${code}`);
console.log(`  email: ${testEmail}`);
console.log(`  pin:   ${pin}`);
