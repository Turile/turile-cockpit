-- Phase 1 baseline · enums and shared helpers.
-- Turile Cockpit: redeem / booking / exchange / balance platform.
-- Money truth lives in Shopify gift cards; this schema is the experience +
-- booking layer only. See turile-platform-spec.md v0.1.

create type public.booking_mode as enum ('api', 'request');
create type public.connector_driver as enum ('octo', 'bokun', 'none');
create type public.provider_status as enum ('draft', 'active', 'paused');
create type public.provider_payout_method as enum ('stripe_connect', 'invoice', 'manual');
create type public.experience_status as enum ('draft', 'active', 'archived');
create type public.voucher_status as enum ('issued', 'activated', 'partially_used', 'depleted', 'expired_dormant');
create type public.booking_status as enum ('draft', 'hold', 'pending_provider', 'confirmed', 'completed', 'cancelled', 'failed');
create type public.provider_response as enum ('pending', 'accepted', 'alternative_proposed', 'declined');
create type public.exchange_status as enum ('pending_topup', 'completed', 'cancelled');
create type public.payout_settlement_method as enum ('stripe_connect', 'invoice_received');
create type public.payout_status as enum ('pending', 'paid', 'reconciled');

create or replace function public.set_updated_at()
returns trigger
language plpgsql
set search_path = public
as $$
begin
  new.updated_at := now();
  return new;
end;
$$;

create or replace function public.forbid_mutation()
returns trigger
language plpgsql
set search_path = public
as $$
begin
  raise exception '% is append-only', tg_table_name;
end;
$$;
