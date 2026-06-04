import { ACCESS_TOKEN_HEADER, type AccessTokenHeader } from "./header";
import type { AccessTokenPayload } from "./payloads";

export const ACCESS_TTL_DEFAULT = 900 as const;
export const ACCESS_TTL_MAX = 3600 as const;
export const ACCESS_MAC_ALG = "H1" as const;
export const SESSION_SECRET_BYTES = 16 as const;

export type AccessMacAlg = typeof ACCESS_MAC_ALG;

export interface AccessPolicy {
  readonly hd: AccessTokenHeader;
  readonly alg: AccessMacAlg;
  readonly ttl: number;
  readonly max: typeof ACCESS_TTL_MAX;
  readonly sz: typeof SESSION_SECRET_BYTES;
}

export interface AccessSeed {
  readonly su: string;
  readonly jt: string;
  readonly ia: number;
  readonly sc: readonly string[];
  readonly ttl?: number;
}

export interface MacKey {
  readonly alg: AccessMacAlg;
  readonly sec: Uint8Array;
}

export interface Mac {
  sign(data: string, key: MacKey): Promise<string>;
  verify(data: string, sig: string, key: MacKey): Promise<boolean>;
}

export function capAccessTtl(ttl: number): number {
  if (!Number.isFinite(ttl) || ttl <= 0) {
    throw new RangeError("Access token TTL must be a positive finite number.");
  }

  return Math.min(Math.floor(ttl), ACCESS_TTL_MAX);
}

export function createAccessPolicy(ttl = ACCESS_TTL_DEFAULT): AccessPolicy {
  return {
    hd: ACCESS_TOKEN_HEADER,
    alg: ACCESS_MAC_ALG,
    ttl: capAccessTtl(ttl),
    max: ACCESS_TTL_MAX,
    sz: SESSION_SECRET_BYTES,
  };
}

export function createAccessTokenPayload(
  input: AccessSeed,
): AccessTokenPayload {
  const ttl = capAccessTtl(input.ttl ?? ACCESS_TTL_DEFAULT);

  return {
    su: input.su,
    jt: input.jt,
    ia: input.ia,
    ex: input.ia + ttl,
    sc: input.sc,
  };
}

export function isSessionSecret(secret: Uint8Array): boolean {
  return secret.byteLength === SESSION_SECRET_BYTES;
}
