-- Phase 1 · providers, experiences (minimal master catalog), connector mappings.

create table public.providers (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  slug text not null unique,
  booking_mode public.booking_mode not null default 'request',
  connector_driver public.connector_driver not null default 'none',
  connector_config jsonb not null default '{}'::jsonb,
  contact_email text,
  payout_method public.provider_payout_method not null default 'manual',
  stripe_account_id text,
  commission_rate numeric(5,2) check (commission_rate is null or commission_rate between 0 and 100),
  cancellation_policy text,
  crm_provider_id uuid,
  status public.provider_status not null default 'draft',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  -- api mode is meaningless without a connector driver
  constraint providers_api_mode_needs_driver
    check (booking_mode <> 'api' or connector_driver <> 'none'),
  -- an active request-mode provider must be reachable for magic-link emails
  constraint providers_active_request_needs_email
    check (status <> 'active' or booking_mode <> 'request' or contact_email is not null)
);

comment on column public.providers.crm_provider_id is
  'Soft link to providers.id in the justvibe-ops CRM (separate Lovable Cloud Supabase project). Deliberately NO foreign key: different database, one-way import only. On import, carry commission_rate and cancellation_policy from the CRM row.';
comment on column public.providers.connector_config is
  'Driver-specific NON-secret config (endpoint, supplier id, ...). Secrets never live here — secret references only; actual keys go in Supabase Vault / function env.';
comment on column public.providers.commission_rate is
  'Percent Turile retains per redemption. Seeded from the CRM on import; used by payouts (Phase 4).';
comment on column public.providers.cancellation_policy is
  'Provider cancellation/reschedule/no-show policy text, shown to the recipient before redemption. Seeded from the CRM on import.';

create trigger providers_set_updated_at
  before update on public.providers
  for each row execute function public.set_updated_at();

create table public.experiences (
  id uuid primary key default gen_random_uuid(),
  provider_id uuid not null references public.providers(id) on delete restrict,
  title text not null,
  slug text not null unique,
  retail_price_cents integer not null check (retail_price_cents >= 0),
  currency char(3) not null default 'CAD',
  shopify_product_id bigint,
  shopify_variant_id bigint,
  status public.experience_status not null default 'draft',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index experiences_provider_idx on public.experiences (provider_id);
create unique index experiences_shopify_product_key
  on public.experiences (shopify_product_id) where shopify_product_id is not null;

create trigger experiences_set_updated_at
  before update on public.experiences
  for each row execute function public.set_updated_at();

create table public.connector_mappings (
  id uuid primary key default gen_random_uuid(),
  experience_id uuid not null unique references public.experiences(id) on delete cascade,
  driver public.connector_driver not null check (driver <> 'none'),
  external_product_id text not null,
  external_option_id text,
  external_unit_id text,
  raw_meta jsonb not null default '{}'::jsonb
);

comment on table public.connector_mappings is
  'One experience ↔ one bookable unit in an external system (OCTO productId/optionId/unitId, Bokun equivalents). Only the connector layer may interpret these fields.';

-- ── RLS posture ──────────────────────────────────────────────────────────────
-- Recipient-facing traffic goes through Edge Functions with the service role.
-- The anon/authenticated clients get NO direct table access, with a single
-- exception: public read of ACTIVE experiences (catalog browsing).

alter table public.providers enable row level security;
alter table public.experiences enable row level security;
alter table public.connector_mappings enable row level security;

revoke all on public.providers from anon, authenticated;
revoke all on public.connector_mappings from anon, authenticated;
revoke all on public.experiences from anon, authenticated;

grant select on public.experiences to anon, authenticated;
create policy "public read active experiences"
  on public.experiences for select
  to anon, authenticated
  using (status = 'active');
