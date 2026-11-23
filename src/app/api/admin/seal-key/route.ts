import { NextResponse } from "next/server";

import { requireAdminSession } from "@/lib/auth/admin";
import { logRouteError } from "@/lib/security/logging";
import {
  applyRateLimit,
  buildRateLimitKey,
} from "@/lib/security/route-controls";
import {
  getClientIpAddress,
  getRequestPathname,
  getRequestUserAgent,
} from "@/lib/security/request";
import {
  getSealKeyStatus,
  replaceUnreadableSealKey,
  SealKeyError,
} from "@/lib/services/seal-identity";

const noStore = { "cache-control": "private, no-store" };

// The key this site seals finished documents with. Administrators only.
// When the auth secret changes, the stored key can no longer be read and
// sealing stops; nothing replaces the key until an administrator says so
// here.

export async function GET(request: Request) {
  const sessionResult = await requireAdminSession(request);

  if (sessionResult instanceof Response) {
    return sessionResult;
  }

  return NextResponse.json(
    { status: await getSealKeyStatus() },
    { headers: noStore },
  );
}

export async function POST(request: Request) {
  const sessionResult = await requireAdminSession(request);

  if (sessionResult instanceof Response) {
    return sessionResult;
  }

  const session = sessionResult;
  const rateLimitResponse = await applyRateLimit({
    category: "seal_key_replace",
    key: buildRateLimitKey(["seal-key-replace", session.user.id]),
    limit: 5,
    request,
    userId: session.user.id,
    windowMs: 10 * 60 * 1000,
  });

  if (rateLimitResponse) {
    return rateLimitResponse;
  }

  try {
    await replaceUnreadableSealKey({
      email: session.user.email,
      ipAddress: getClientIpAddress(request.headers),
      userAgent: getRequestUserAgent(request.headers),
      userId: session.user.id,
    });

    return NextResponse.json(
      { status: await getSealKeyStatus() },
      { headers: noStore },
    );
  } catch (error) {
    if (error instanceof SealKeyError && error.statusCode < 500) {
      return NextResponse.json(
        { error: error.message },
        { headers: noStore, status: error.statusCode },
      );
    }

    logRouteError(error, {
      category: "seal_key_replace_failure",
      ipAddress: getClientIpAddress(request.headers),
      message: "Unexpected failure while making a new sealing key.",
      path: getRequestPathname(request),
      userId: session.user.id,
    });

    return NextResponse.json(
      { error: "A new sealing key could not be made." },
      { headers: noStore, status: 500 },
    );
  }
}
