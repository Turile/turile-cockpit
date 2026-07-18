-- Phase 1 · voucher access PIN + per-voucher brute-force accounting.
-- NOTE ON NAMING: "access PIN" is the 4-digit secret the recipient enters at
-- activation. It is UNRELATED to the experience pin (pinned_experience_id /
-- pin_expires_at). Never use a bare "pin" column name in this table.

alter table public.vouchers
  add column access_pin_salt text,
  add column access_pin_hash text,
  add column activation_fail_count integer not null default 0,
  add column activation_last_failed_at timestamptz,
  add constraint vouchers_access_pin_pair
    check ((access_pin_hash is null) = (access_pin_salt is null));

comment on column public.vouchers.access_pin_salt is
  'Per-voucher random salt (hex) for the access PIN KDF. Defeats rainbow tables over the tiny 10^4 PIN space.';
comment on column public.vouchers.access_pin_hash is
  'Versioned slow-KDF digest of the 4-digit access PIN: ''v1$'' + hex(scrypt(pin, salt, N=16384, r=8, p=1, len=32)). Never a bare SHA-256. NULL = no PIN issued yet → activation fails closed (404, same body as not-found) until ops backfills one. Will become NOT NULL once the issuance flow guarantees a PIN.';
comment on column public.vouchers.activation_fail_count is
  'Failed activation attempts against THIS voucher (wrong email or PIN after code matched). Drives the tarpit delay in activate-voucher; reset to 0 on success. Orthogonal to per-IP limits in activation_attempts.';

-- Atomic failure accounting: increments the counter and emits a one-time
-- ops event at the suspicion threshold. Called by activate-voucher only.
create or replace function public.record_voucher_activation_failure(p_voucher_id uuid)
returns integer
language plpgsql
security definer
set search_path = public
as $$
declare
  new_count integer;
begin
  update public.vouchers
     set activation_fail_count = activation_fail_count + 1,
         activation_last_failed_at = now()
   where id = p_voucher_id
   returning activation_fail_count into new_count;

  if new_count = 20 then
    insert into public.events (entity_type, entity_id, event, actor, payload)
    values ('voucher', p_voucher_id, 'voucher.bruteforce_suspected', 'system',
            jsonb_build_object('activation_fail_count', new_count));
  end if;

  return new_count;
end;
$$;

revoke execute on function public.record_voucher_activation_failure(uuid) from public, anon, authenticated;
