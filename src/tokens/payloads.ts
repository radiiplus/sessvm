export interface AccessTokenPayload {
  readonly su: string;
  readonly jt: string;
  readonly ia: number;
  readonly ex: number;
  readonly sc: readonly string[];
}

export interface RefreshTokenPayload {
  readonly su: string;
  readonly si: string;
  readonly jt: string;
  readonly ia: number;
  readonly ex: number;
  readonly bh: string;
}

export type SessionTokenPayload = AccessTokenPayload | RefreshTokenPayload;

export function isAccessTokenPayload(
  payload: SessionTokenPayload,
): payload is AccessTokenPayload {
  return "jt" in payload;
}

export function isRefreshTokenPayload(
  payload: SessionTokenPayload,
): payload is RefreshTokenPayload {
  return "bh" in payload;
}
