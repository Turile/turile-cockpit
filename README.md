# Turile Cockpit

Standalone redeem / booking / exchange / balance platform for Turile gifts
(`redeem.turile.ca`). Everything that happens *after* a gift is purchased on
the Shopify storefront. Spec: `turile-platform-spec.md` v0.1.

**Core principles (locked):**
- Money lives in Shopify gift cards — no parallel wallet, balance always read live.
- The voucher shows an experience but stores money; exchange = re-pointing the pin.
- Booking state machine lives here; connector abstraction (`octo`, `bokun`) from day one.
- Vouchers never expire monetarily (BC BPCPA / Alberta CPA); the experience pin
  lasts 12 months from purchase, then converts to open balance.

**Stack:** Supabase (Postgres + RLS + Edge Functions, own account — never
Lovable Cloud) · React + Vite + Tailwind · Resend · Shopify Admin API.

**Conventions:**
- Every schema change is a migration file in `supabase/migrations/` — no
  dashboard-only edits.
- Secrets only in Supabase Vault / env; never in `connector_config` or the repo.
- Every edge function declares `verify_jwt` explicitly in `supabase/config.toml`.
- Anon clients get no table access except reading active `experiences`;
  recipient-facing endpoints go through edge functions with the service role.
- All magic-link / voucher tokens are stored as SHA-256 hashes with expiry,
  never plaintext.

The `justvibe-ops` CRM repo is a read-only reference (cloned at
`~/Desktop/_reference/justvibe-ops`), linked softly via
`providers.crm_provider_id` — never a dependency.
