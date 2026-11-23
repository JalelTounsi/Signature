-- A send or a reminder whose email fails is undone. The audit event it
-- wrote used to be deleted from the envelope's hash chain. It now stays,
-- and the reversal is recorded after it as an event of its own.

alter table public.audit_events
  drop constraint if exists audit_events_event_check;

alter table public.audit_events
  add constraint audit_events_event_check
    check (event in (
      'created',
      'sent',
      'viewed',
      'consented',
      'verified',
      'verification_failed',
      'signed',
      'declined',
      'reminded_manual',
      'email_sent',
      'completed',
      'voided',
      'deadline_changed',
      'expired',
      'reminded_auto',
      'reauthentication_failed',
      'copied',
      'signer_corrected',
      'approved',
      'rejected',
      'send_reverted',
      'reminder_reverted'
    ));
