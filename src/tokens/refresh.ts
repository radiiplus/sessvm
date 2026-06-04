import { REFRESH_TOKEN_HEADER, type RefreshTokenHeader } from "./header";
import type { DeviceFingerprint } from "../fingerprint";
import type { RefreshTokenPayload } from "./payloads";

export const REFRESH_MAC_ALG = "H2" as const;
export const REFRESH_TTL_DEFAULT = 2_592_000 as const;
export const REFRESH_SECRET_BYTES = 32 as const;

export type RefreshMacAlg = typeof REFRESH_MAC_ALG;

export interface RefreshPolicy {
  readonly hd: RefreshTokenHeader;
  readonly alg: RefreshMacAlg;
  readonly kid: string;
  readonly ttl: number;
  readonly sz: typeof REFRESH_SECRET_BYTES;
}

export interface RefreshSeed {
  readonly su: string;
  readonly si: string;
  readonly jt: string;
  readonly ia: number;
  readonly ttl?: number;
  readonly bh: string;
}

export interface RefreshVal {
  readonly hd: RefreshTokenHeader;
  readonly kid: string;
  readonly val: string;
}

export interface Rng {
  bytes(size: number): Uint8Array;
}

export interface BindIn {
  readonly j24: string;
  readonly uag: string;
}

export interface BindMac {
  sign(data: string, key: Uint8Array): Promise<string>;
}

function getRuntimeCrypto(): Crypto {
  if (typeof globalThis.crypto === "undefined") {
    throw new Error("Web Crypto is required to generate refresh tokens.");
  }

  return globalThis.crypto;
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = "";

  for (const byte of bytes) {
    hex += byte.toString(16).padStart(2, "0");
  }

  return hex;
}

function safeEq(left: string, right: string): boolean {
  const size = Math.max(left.length, right.length);
  let diff = left.length ^ right.length;

  for (let index = 0; index < size; index += 1) {
    const leftCode = index < left.length ? left.charCodeAt(index) : 0;
    const rightCode = index < right.length ? right.charCodeAt(index) : 0;
    diff |= leftCode ^ rightCode;
  }

  return diff === 0;
}

export const webRng: Rng = {
  bytes(size: number): Uint8Array {
    if (!Number.isInteger(size) || size <= 0) {
      throw new RangeError("Random byte size must be a positive integer.");
    }

    return getRuntimeCrypto().getRandomValues(new Uint8Array(size));
  },
};

export function createRefreshPolicy(
  kid: string,
  ttl = REFRESH_TTL_DEFAULT,
): RefreshPolicy {
  if (kid.length === 0) {
    throw new RangeError("Refresh policy kid must not be empty.");
  }

  if (!Number.isFinite(ttl) || ttl <= 0) {
    throw new RangeError("Refresh token TTL must be a positive finite number.");
  }

  return {
    hd: REFRESH_TOKEN_HEADER,
    alg: REFRESH_MAC_ALG,
    kid,
    ttl: Math.floor(ttl),
    sz: REFRESH_SECRET_BYTES,
  };
}

export function createRefreshTokenPayload(
  input: RefreshSeed,
): RefreshTokenPayload {
  const ttl = input.ttl ?? REFRESH_TTL_DEFAULT;

  if (!Number.isFinite(ttl) || ttl <= 0) {
    throw new RangeError("Refresh token TTL must be a positive finite number.");
  }

  return {
    su: input.su,
    si: input.si,
    jt: input.jt,
    ia: input.ia,
    ex: input.ia + Math.floor(ttl),
    bh: input.bh,
  };
}

export function isRefreshSecret(secret: Uint8Array): boolean {
  return secret.byteLength >= REFRESH_SECRET_BYTES;
}

export function createBindingInput(input: BindIn): string {
  return `${input.j24}.${input.uag}`;
}

function part(value: string | null | undefined): string {
  return value ?? "";
}

export function createBindingParts(
  fingerprint: DeviceFingerprint,
): readonly [string, string, string, string, string, string] {
  return [
    part(fingerprint.ua),
    part(fingerprint.al),
    part(fingerprint.ja),
    part(fingerprint.ip),
    part(fingerprint.br),
    part(fingerprint.bv),
  ];
}

export function createBindingInputFromFingerprint(
  fingerprint: DeviceFingerprint,
): string {
  return createBindingParts(fingerprint).join("|");
}

export function createBindingFromFingerprint(
  fingerprint: DeviceFingerprint,
): BindIn {
  return {
    j24: createBindingInputFromFingerprint(fingerprint),
    uag: fingerprint.ua,
  };
}

export function createRefreshValue(
  policy: RefreshPolicy,
  rng: Rng = webRng,
): RefreshVal {
  const secret = rng.bytes(policy.sz);

  if (!isRefreshSecret(secret)) {
    throw new RangeError("Refresh token generators must emit at least 32 bytes.");
  }

  return {
    hd: policy.hd,
    kid: policy.kid,
    val: bytesToHex(secret),
  };
}

export async function createBindingHash(
  input: BindIn,
  key: Uint8Array,
  mac: BindMac,
): Promise<string> {
  return mac.sign(createBindingInput(input), key);
}

export async function verifyBindingHash(
  expected: string,
  input: BindIn,
  key: Uint8Array,
  mac: BindMac,
): Promise<boolean> {
  const actual = await createBindingHash(input, key, mac);
  return safeEq(expected, actual);
}
