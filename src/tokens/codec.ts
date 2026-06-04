import { ACCESS_TOKEN_HEADER, type TokenHeader } from "./header";
import {
  type AccessPolicy,
  type Mac,
  type MacKey,
} from "./access";
import type { AccessTokenPayload } from "./payloads";

function encodeJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

function decodeJson<T>(value: string): T {
  return JSON.parse(Buffer.from(value, "base64url").toString("utf8")) as T;
}

export interface SerializedAccessToken {
  readonly hd: typeof ACCESS_TOKEN_HEADER;
  readonly pl: string;
  readonly sg: string;
  readonly tk: string;
}

export async function signAccessToken(
  payload: AccessTokenPayload,
  key: MacKey,
  mac: Mac,
  header: TokenHeader = ACCESS_TOKEN_HEADER,
): Promise<SerializedAccessToken> {
  const pl = encodeJson(payload);
  const data = `${header}.${pl}`;
  const sg = await mac.sign(data, key);

  return {
    hd: ACCESS_TOKEN_HEADER,
    pl,
    sg,
    tk: `${header}.${pl}.${sg}`,
  };
}

export async function verifyAccessToken(
  token: string,
  key: MacKey,
  mac: Mac,
  policy: AccessPolicy,
): Promise<AccessTokenPayload | null> {
  const parts = token.split(".");

  if (parts.length !== 3) {
    return null;
  }

  const hd = parts[0];
  const pl = parts[1];
  const sg = parts[2];

  if (hd === undefined || pl === undefined || sg === undefined) {
    return null;
  }

  if (hd !== policy.hd) {
    return null;
  }

  const ok = await mac.verify(`${hd}.${pl}`, sg, key);

  if (!ok) {
    return null;
  }

  const payload = decodeJson<AccessTokenPayload>(pl);

  if (payload.ex - payload.ia > policy.max) {
    return null;
  }

  return payload;
}

export async function parseAccessToken(
  token: string,
  key: MacKey,
  mac: Mac,
  policy: AccessPolicy,
): Promise<AccessTokenPayload | null> {
  const parts = token.split(".");

  if (parts.length !== 3) {
    return null;
  }

  const hd = parts[0];
  const pl = parts[1];
  const sg = parts[2];

  if (hd === undefined || pl === undefined || sg === undefined) {
    return null;
  }

  if (hd !== policy.hd) {
    return null;
  }

  const ok = await mac.verify(`${hd}.${pl}`, sg, key);

  if (!ok) {
    return null;
  }

  const payload = decodeJson<AccessTokenPayload>(pl);

  if (payload.ex - payload.ia > policy.max) {
    return null;
  }

  return payload;
}
