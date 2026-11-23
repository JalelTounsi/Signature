"use client";

import { useEffect, useState } from "react";

// Shown only when the stored sealing key can no longer be read, which
// happens when the auth secret changes. Administrators only.

const GENERIC_ERROR_MESSAGE = "Something went wrong. Please try again.";

export function SealKeyPanel() {
  const [status, setStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isSaving, setIsSaving] = useState(false);

  useEffect(() => {
    let cancelled = false;

    void (async () => {
      try {
        const response = await fetch("/api/admin/seal-key", {
          cache: "no-store",
        });
        const payload = (await response.json().catch(() => null)) as {
          status?: string;
        } | null;

        if (!cancelled && response.ok && payload?.status) {
          setStatus(payload.status);
        }
      } catch {
        // Nothing to show: the audit trail below still has the event.
      }
    })();

    return () => {
      cancelled = true;
    };
  }, []);

  async function makeNewKey() {
    setIsSaving(true);
    setError(null);

    try {
      const response = await fetch("/api/admin/seal-key", { method: "POST" });
      const payload = (await response.json().catch(() => null)) as {
        error?: string;
        status?: string;
      } | null;

      if (!response.ok || !payload?.status) {
        setError(payload?.error ?? GENERIC_ERROR_MESSAGE);
        return;
      }

      setStatus(payload.status);
    } catch {
      setError(GENERIC_ERROR_MESSAGE);
    } finally {
      setIsSaving(false);
    }
  }

  if (status !== "unreadable") {
    return null;
  }

  return (
    <div className="space-y-5 border-t border-(--border) pt-8" id="seal-key">
      <div className="space-y-2">
        <h3 className="text-lg font-extrabold tracking-[-0.02em] text-(--fg)">
          Sealing key
        </h3>
        <div className="notice notice-danger" role="alert">
          Documents cannot be sealed. The key this site seals them with was
          stored under a different BETTER_AUTH_SECRET (or database password)
          than the one set now, so it can no longer be read.
        </div>
        <p className="max-w-2xl text-sm leading-6 text-(--secondary)">
          If the secret was changed by mistake, put the earlier one back and
          deploy again: the same key then works as before. Otherwise make a new
          key. Documents sealed before still verify, under the old certificate;
          documents sealed from now on carry a new one. The change is recorded
          in the audit trail.
        </p>
      </div>

      {error ? (
        <div className="notice notice-danger" role="alert">
          {error}
        </div>
      ) : null}

      <button
        className="btn-quiet"
        disabled={isSaving}
        onClick={() => void makeNewKey()}
        type="button"
      >
        {isSaving ? "Making it..." : "Make a new sealing key"}
      </button>
    </div>
  );
}
