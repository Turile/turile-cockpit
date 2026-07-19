-- Phase 1 fix · provider_token_hash must be nullable: the one-shot token is
-- burned (set to NULL) after the provider responds, which the original
-- NOT NULL constraint forbade — finalize_booking_acceptance/response failed
-- with 23502. UNIQUE stays (Postgres allows multiple NULLs).

alter table public.booking_requests alter column provider_token_hash drop not null;

comment on column public.booking_requests.provider_token_hash is
  'SHA-256 hex of the magic-link token; plaintext exists only in the emailed URL. NULL = token burned after the provider responded (one-shot). New requests must always set it.';
