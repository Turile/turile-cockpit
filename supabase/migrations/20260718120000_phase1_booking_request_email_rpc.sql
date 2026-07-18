-- Phase 1 · booking-request support: CRM-style email send bookkeeping on the
-- entity + atomic booking/request creation RPC.

alter table public.booking_requests
  add column email_sent_at timestamptz,
  add column email_to text,
  add column email_error text;

comment on column public.booking_requests.email_sent_at is
  'When the provider magic-link email was last sent successfully via Resend. Send outcome lives on the entity (pattern proven in the CRM: intake_form_sent_at/_to/_error) so "why did the provider not get the email" is answerable from the row.';
comment on column public.booking_requests.email_error is
  'Last Resend failure, NULL after a successful send. A repeat booking-request call retries the send only while this is set / email_sent_at is empty.';

-- Atomic creation: booking + booking_request + audit event in one transaction.
-- Two separate PostgREST inserts would not be atomic. Called by the
-- booking-request edge function only (service role).
create or replace function public.create_booking_request(
  p_voucher_id uuid,
  p_experience_id uuid,
  p_provider_id uuid,
  p_amount_cents integer,
  p_party_size integer,
  p_proposed_slots jsonb,
  p_token_hash text,
  p_token_expires_at timestamptz
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_booking_id uuid;
  v_request_id uuid;
begin
  insert into public.bookings
    (voucher_id, experience_id, provider_id, mode, status, party_size, amount_cents)
  values
    (p_voucher_id, p_experience_id, p_provider_id, 'request', 'pending_provider', p_party_size, p_amount_cents)
  returning id into v_booking_id;

  insert into public.booking_requests
    (booking_id, proposed_slots, provider_token_hash, token_expires_at)
  values
    (v_booking_id, p_proposed_slots, p_token_hash, p_token_expires_at)
  returning id into v_request_id;

  insert into public.events (entity_type, entity_id, event, actor, payload)
  values ('booking', v_booking_id, 'booking.created', 'recipient',
          jsonb_build_object(
            'voucher_id', p_voucher_id,
            'experience_id', p_experience_id,
            'mode', 'request',
            'party_size', p_party_size,
            'slots_count', jsonb_array_length(p_proposed_slots),
            'request_id', v_request_id));

  return jsonb_build_object('booking_id', v_booking_id, 'request_id', v_request_id);
end;
$$;

revoke execute on function public.create_booking_request(uuid, uuid, uuid, integer, integer, jsonb, text, timestamptz) from public, anon, authenticated;
