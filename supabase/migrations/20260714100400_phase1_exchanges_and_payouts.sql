-- Phase 1 · exchanges (re-pin, optional Shopify top-up) + payouts stub (Phase 4).

create table public.exchanges (
  id uuid primary key default gen_random_uuid(),
  voucher_id uuid not null references public.vouchers(id) on delete restrict,
  from_experience_id uuid references public.experiences(id) on delete set null,
  to_experience_id uuid not null references public.experiences(id) on delete restrict,
  price_delta_cents integer not null,
  topup_shopify_order_id bigint,
  status public.exchange_status not null,
  created_at timestamptz not null default now(),
  -- pending_topup only exists when the recipient actually owes a delta
  constraint exchanges_topup_needs_positive_delta
    check (status <> 'pending_topup' or price_delta_cents > 0)
);

comment on table public.exchanges is
  'Exchange = re-pointing vouchers.pinned_experience_id, never moving money. Equal/cheaper: instant re-pin, remainder stays on the Shopify balance. More expensive: recipient pays price_delta_cents via a Shopify checkout (topup_shopify_order_id); the orders/paid webhook completes the exchange.';

create index exchanges_voucher_idx on public.exchanges (voucher_id);

create table public.payouts (
  id uuid primary key default gen_random_uuid(),
  booking_id uuid not null references public.bookings(id) on delete restrict,
  provider_id uuid not null references public.providers(id) on delete restrict,
  amount_cents integer not null check (amount_cents >= 0),
  commission_cents integer not null check (commission_cents >= 0),
  method public.payout_settlement_method not null,
  status public.payout_status not null default 'pending',
  paid_at timestamptz,
  created_at timestamptz not null default now()
);

comment on table public.payouts is
  'Phase 4 stub — created now so Phase 1 FKs and the events log do not need reshaping later. amount_cents = net to provider, commission_cents = Turile margin.';

create index payouts_provider_status_idx on public.payouts (provider_id, status);

alter table public.exchanges enable row level security;
alter table public.payouts enable row level security;
revoke all on public.exchanges from anon, authenticated;
revoke all on public.payouts from anon, authenticated;
