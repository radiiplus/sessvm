import { timingSafeEqual } from "node:crypto";
import type { RequestLike } from "./fingerprint";

export const CSRF_HEADER = "x-csrf-token" as const;
export const CSRF_COOKIE = "csrf" as const;

export interface CsrfIn {
  readonly cookie: string | null;
  readonly header: string | null;
}

export interface CsrfOut {
  readonly ok: boolean;
  readonly rsn?: "missing-csrf-cookie" | "missing-csrf-header" | "csrf-mismatch";
}

export interface CsrfReq extends RequestLike {
  readonly cookies?: Record<string, string | undefined> | null;
}

function safeEqual(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left, "utf8");
  const rightBuffer = Buffer.from(right, "utf8");

  if (leftBuffer.length !== rightBuffer.length) {
    return false;
  }

  return timingSafeEqual(leftBuffer, rightBuffer);
}

function parseCookie(source: string | null, name: string): string | null {
  if (source === null) {
    return null;
  }

  const target = `${name}=`;

  for (const raw of source.split(";")) {
    const part = raw.trim();

    if (part.startsWith(target)) {
      return decodeURIComponent(part.slice(target.length));
    }
  }

  return null;
}

export function csi(input: CsrfIn): CsrfOut {
  if (input.cookie === null || input.cookie.length === 0) {
    return {
      ok: false,
      rsn: "missing-csrf-cookie",
    };
  }

  if (input.header === null || input.header.length === 0) {
    return {
      ok: false,
      rsn: "missing-csrf-header",
    };
  }

  if (!safeEqual(input.cookie, input.header)) {
    return {
      ok: false,
      rsn: "csrf-mismatch",
    };
  }

  return {
    ok: true,
  };
}

export function csr(
  request: CsrfReq,
  cookieName = CSRF_COOKIE,
  headerName = CSRF_HEADER,
): CsrfOut {
  const cookie =
    request.cookies?.[cookieName] ??
    parseCookie(request.headers.get("cookie"), cookieName);

  return csi({
    cookie,
    header: request.headers.get(headerName),
  });
}
