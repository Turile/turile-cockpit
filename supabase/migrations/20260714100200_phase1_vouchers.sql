-- Phase 1 · vouchers: the experience-layer wrapper around Shopify gift cards.

create table public.vouchers (
  id uuid primary key default gen_random_uuid(),
  code_hash text not null unique,
  code_last4 text not null check (char_length(code_last4) = 4),
  shopify_gift_card_id bigint not null unique,
  shopify_order_id bigint not null,
  initial_value_cents integer not null check (initial_value_cents > 0),
  pinned_experience_id uuid references public.experiences(id) on delete set null,
  purchased_at timestamptz not null,
  pin_expires_at timestamptz,
  purchaser_email text not null,
  recipient_email text,
  status public.voucher_status not null default 'issued',
  activated_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  -- a pin expiry only makes sense while an experience is pinned
  constraint vouchers_pin_expiry_needs_pin
    check (pinned_experience_id is not null or pin_expires_at is null)
);

comment on table public.vouchers is
  'Experience-layer ledger per gifted voucher. MONETARY VALUE NEVER EXPIRES: Canadian consumer-protection law (BC Business Practices and Consumer Protection Act; Alberta Consumer Protection Act) and the provider contract (clause 3.2, "No expiry") both forbid it. Balance is always read live from the Shopify gift card API — never cached as truth. Only the experience PIN is time-limited (see pin_expires_at); voucher_status ''expired_dormant'' marks dormancy for ops follow-up, never loss of funds.';
comment on column public.vouchers.code_hash is
  'SHA-256 hex of the full voucher code. Plaintext codes are never stored or returned by queries; lookups hash the submitted code first.';
comment on column public.vouchers.code_last4 is
  'Last 4 characters of the code, for support/UI display only.';
comment on column public.vouchers.purchased_at is
  'Shopify order timestamp — anchors the 12-month pin window.';
comment on column public.vouchers.pin_expires_at is
  'purchased_at + 12 months (decision 2026-07: open decision #2 in spec §9). Past this moment the pinned experience converts to open balance: pin cleared, money untouched, conversion logged to events. Exchanges re-pin within the same window.';
comment on column public.vouchers.pinned_experience_id is
  'The experience shown on the gift. NULL = pure monetary gift card (or pin already converted to open balance).';

create index vouchers_status_idx on public.vouchers (status);
create index vouchers_pin_expiry_idx on public.vouchers (pin_expires_at)
  where pinned_experience_id is not null;

create trigger vouchers_set_updated_at
  before update on public.vouchers
  for each row execute function public.set_updated_at();

alter table public.vouchers enable row level security;
revoke all on public.vouchers from anon, authenticated;
