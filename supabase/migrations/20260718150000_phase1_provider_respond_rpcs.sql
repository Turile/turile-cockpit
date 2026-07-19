-- Phase 1 · provider-respond finalization RPCs.
-- Accept path is a 3-step saga in the edge function (atomic claim →
-- Shopify redeem → finalize); this migration provides the transactional
-- steps that must not be split across PostgREST calls.

-- Step C of the accept saga: everything after a successful gift-card debit,
-- in ONE transaction. The claim (provider_response pending→accepted) already
-- happened; redeem already happened. Burns the one-shot token.
create or replace function public.finalize_booking_acceptance(
  p_request_id uuid,
  p_booking_id uuid,
  p_voucher_id uuid,
  p_slot_start timestamptz,
  p_slot_end timestamptz,
  p_voucher_status public.voucher_status,
  p_redeem_payload jsonb
)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  update public.bookings
     set status = 'confirmed', slot_start = p_slot_start, slot_end = p_slot_end
   where id = p_booking_id and status = 'pending_provider';

  update public.booking_requests
     set provider_token_hash = null
   where id = p_request_id;

  update public.vouchers
     set status = p_voucher_status
   where id = p_voucher_id;

  insert into public.events (entity_type, entity_id, event, actor, payload)
  values
    ('voucher', p_voucher_id, 'voucher.redeemed', 'system', p_redeem_payload),
    ('booking', p_booking_id, 'booking.confirmed', 'provider',
     jsonb_build_object('request_id', p_request_id,
                        'slot_start', p_slot_start, 'slot_end', p_slot_end));
end;
$$;

-- Decline / propose_alternative: claim + booking failed + audit event +
-- token burn, atomically. Returns false if the request was no longer
-- pending (lost race / already responded) — caller maps that to 404.
-- Money never moves on these paths, so the voucher immediately becomes
-- bookable again: booking-request only blocks on pending_provider/hold/
-- confirmed, and this sets the booking to 'failed'.
create or replace function public.finalize_booking_response(
  p_request_id uuid,
  p_booking_id uuid,
  p_response public.provider_response,
  p_event_payload jsonb
)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
begin
  if p_response not in ('declined', 'alternative_proposed') then
    raise exception 'finalize_booking_response: unsupported response %', p_response;
  end if;

  update public.booking_requests
     set provider_response = p_response,
         responded_at = now(),
         provider_token_hash = null
   where id = p_request_id and provider_response = 'pending';
  if not found then
    return false;
  end if;

  update public.bookings
     set status = 'failed'
   where id = p_booking_id and status = 'pending_provider';

  insert into public.events (entity_type, entity_id, event, actor, payload)
  values ('booking', p_booking_id,
          case when p_response = 'declined' then 'booking.declined'
               else 'booking.alternative_proposed' end,
          'provider', p_event_payload);

  return true;
end;
$$;

revoke execute on function public.finalize_booking_acceptance(uuid, uuid, uuid, timestamptz, timestamptz, public.voucher_status, jsonb) from public, anon, authenticated;
revoke execute on function public.finalize_booking_response(uuid, uuid, public.provider_response, jsonb) from public, anon, authenticated;
