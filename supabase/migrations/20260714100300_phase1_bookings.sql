-- Phase 1 · bookings + request-flow (provider magic-link confirmation).

create table public.bookings (
  id uuid primary key default gen_random_uuid(),
  voucher_id uuid not null references public.vouchers(id) on delete restrict,
  experience_id uuid not null references public.experiences(id) on delete restrict,
  provider_id uuid not null references public.providers(id) on delete restrict,
  mode public.booking_mode not null,
  status public.booking_status not null default 'draft',
  slot_start timestamptz,
  slot_end timestamptz,
  party_size integer not null default 1 check (party_size >= 1),
  external_booking_ref text,
  hold_expires_at timestamptz,
  amount_cents integer not null default 0 check (amount_cents >= 0),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint bookings_slot_range
    check (slot_end is null or (slot_start is not null and slot_end > slot_start))
);

comment on table public.bookings is
  'Booking state machine (spec §4). ORDERING RULE: gift-card value is redeemed against Shopify only between successful hold/acceptance and confirm, atomically with the connector confirm call; if confirm fails, the redeem is reversed and status → failed. Never leave money captured against a non-existent booking. Status transitions are advance-only via a ranking map in the app layer (pattern proven in the CRM) and every transition writes an events row.';
comment on column public.bookings.hold_expires_at is
  'api mode only: when the connector hold lapses. A scheduled function auto-releases expired holds → failed, nothing charged.';

create index bookings_voucher_idx on public.bookings (voucher_id);
create index bookings_provider_status_idx on public.bookings (provider_id, status);
create index bookings_hold_expiry_idx on public.bookings (hold_expires_at)
  where status = 'hold';

create trigger bookings_set_updated_at
  before update on public.bookings
  for each row execute function public.set_updated_at();

create table public.booking_requests (
  id uuid primary key default gen_random_uuid(),
  booking_id uuid not null references public.bookings(id) on delete cascade,
  proposed_slots jsonb not null,
  provider_token_hash text not null unique,
  token_expires_at timestamptz not null,
  provider_response public.provider_response not null default 'pending',
  accepted_slot jsonb,
  responded_at timestamptz,
  created_at timestamptz not null default now(),
  constraint booking_requests_slots_shape check (
    jsonb_typeof(proposed_slots) = 'array'
    and jsonb_array_length(proposed_slots) between 1 and 3
  )
);

comment on table public.booking_requests is
  'Request-mode flow: recipient proposes 2–3 slots (UI enforces the minimum of 2; schema allows 1 for ops edge cases), provider confirms via magic link emailed through Resend. Send attempts/errors are recorded on the entity, CRM-style.';
comment on column public.booking_requests.provider_token_hash is
  'SHA-256 hex of the magic-link token. Plaintext token exists only inside the emailed URL — never stored (deliberate hardening over the CRM, which kept plaintext token columns). Single-use: cleared/invalidated on response; expiry enforced via token_expires_at.';

-- at most one open request per booking
create unique index booking_requests_one_pending_key
  on public.booking_requests (booking_id) where provider_response = 'pending';

alter table public.bookings enable row level security;
alter table public.booking_requests enable row level security;
revoke all on public.bookings from anon, authenticated;
revoke all on public.booking_requests from anon, authenticated;
