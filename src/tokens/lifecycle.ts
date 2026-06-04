import {
  REFRESH_TOKEN_HEADER,
  type RefreshTokenHeader,
  type TokenSchemaVersion,
} from "./header";

export const TOKEN_LIFECYCLE_PHASE_CODES = {
  issued: "I",
  active: "A",
  expired: "E",
  revoked: "V",
  rotated: "O",
  reuseDetected: "U",
} as const;

export type TokenLifecyclePhaseCode =
  (typeof TOKEN_LIFECYCLE_PHASE_CODES)[keyof typeof TOKEN_LIFECYCLE_PHASE_CODES];

export type TokenLifecycleStateCode =
  `${TokenLifecyclePhaseCode}${TokenSchemaVersion}`;

export const ISSUED_STATE = "I1" as const;
export const ACTIVE_STATE = "A1" as const;
export const EXPIRED_STATE = "E1" as const;
export const REVOKED_STATE = "V1" as const;
export const ROTATED_STATE = "O1" as const;
export const REUSE_DETECTED_STATE = "U1" as const;

export type IssuedState = typeof ISSUED_STATE;
export type ActiveState = typeof ACTIVE_STATE;
export type ExpiredState = typeof EXPIRED_STATE;
export type RevokedState = typeof REVOKED_STATE;
export type RotatedState = typeof ROTATED_STATE;
export type ReuseDetectedState = typeof REUSE_DETECTED_STATE;

export type TerminalTokenLifecycleState =
  | ExpiredState
  | RevokedState
  | RotatedState
  | ReuseDetectedState;

export type TokenLifecycleState =
  | IssuedState
  | ActiveState
  | TerminalTokenLifecycleState;

export interface LifecycleTransition<
  TFrom extends TokenLifecycleState = TokenLifecycleState,
  TTo extends TokenLifecycleState = TokenLifecycleState,
> {
  readonly from: TFrom;
  readonly to: TTo;
  readonly occurredAt: number;
  readonly reason?: string;
}

export interface RefreshTokenRecord<
  TState extends TokenLifecycleState = TokenLifecycleState,
> {
  readonly tokenHeader: RefreshTokenHeader;
  readonly tokenId: string;
  readonly familyId: string;
  readonly sessionId: string;
  readonly rotationCounter: number;
  readonly state: TState;
  readonly issuedAt: number;
  readonly expiresAt: number;
  readonly replacedByTokenId?: string;
  readonly revokedReason?: string;
}

export interface RefreshRotationResult {
  readonly predecessor: RefreshTokenRecord<RotatedState>;
  readonly successor: RefreshTokenRecord<IssuedState>;
  readonly transition: LifecycleTransition<ActiveState, RotatedState>;
}

export interface RefreshReuseDetectionResult {
  readonly reusedToken: RefreshTokenRecord<ReuseDetectedState>;
  readonly familyRevocation: LifecycleTransition<RotatedState, ReuseDetectedState>;
}

const TOKEN_LIFECYCLE_PHASE_SET = new Set<TokenLifecyclePhaseCode>(
  Object.values(TOKEN_LIFECYCLE_PHASE_CODES),
);

export function createLifecycleStateCode<
  TPhase extends TokenLifecyclePhaseCode,
  TVersion extends TokenSchemaVersion,
>(phase: TPhase, version: TVersion): `${TPhase}${TVersion}` {
  return `${phase}${version}` as `${TPhase}${TVersion}`;
}

export function isLifecycleStateCode(
  value: string,
): value is TokenLifecycleStateCode {
  if (value.length !== 2) {
    return false;
  }

  const phase = value[0];
  const version = Number(value[1]);

  return (
    TOKEN_LIFECYCLE_PHASE_SET.has(phase as TokenLifecyclePhaseCode) &&
    Number.isInteger(version) &&
    version >= 1 &&
    version <= 9
  );
}

export function activateToken(
  token: RefreshTokenRecord<IssuedState>,
): RefreshTokenRecord<ActiveState> {
  return {
    ...token,
    state: ACTIVE_STATE,
  };
}

export function expireToken<
  TState extends IssuedState | ActiveState,
>(
  token: RefreshTokenRecord<TState>,
): RefreshTokenRecord<ExpiredState> {
  return {
    ...token,
    state: EXPIRED_STATE,
  };
}

export function revokeToken<
  TState extends IssuedState | ActiveState,
>(
  token: RefreshTokenRecord<TState>,
  revokedReason: string,
): RefreshTokenRecord<RevokedState> {
  return {
    ...token,
    state: REVOKED_STATE,
    revokedReason,
  };
}

export function rotateRefreshToken(
  token: RefreshTokenRecord<ActiveState>,
  successorTokenId: string,
  occurredAt: number,
  expiresAt: number,
): RefreshRotationResult {
  const predecessor: RefreshTokenRecord<RotatedState> = {
    ...token,
    state: ROTATED_STATE,
    replacedByTokenId: successorTokenId,
  };

  const successor: RefreshTokenRecord<IssuedState> = {
    tokenHeader: REFRESH_TOKEN_HEADER,
    tokenId: successorTokenId,
    familyId: token.familyId,
    sessionId: token.sessionId,
    rotationCounter: token.rotationCounter + 1,
    state: ISSUED_STATE,
    issuedAt: occurredAt,
    expiresAt,
  };

  return {
    predecessor,
    successor,
    transition: {
      from: ACTIVE_STATE,
      to: ROTATED_STATE,
      occurredAt,
      reason: "refresh-rotated",
    },
  };
}

export function detectRefreshTokenReuse(
  token: RefreshTokenRecord<RotatedState>,
  occurredAt: number,
): RefreshReuseDetectionResult {
  return {
    reusedToken: {
      ...token,
      state: REUSE_DETECTED_STATE,
      revokedReason: "refresh-token-reuse-detected",
    },
    familyRevocation: {
      from: ROTATED_STATE,
      to: REUSE_DETECTED_STATE,
      occurredAt,
      reason: "rotated-token-replayed",
    },
  };
}
