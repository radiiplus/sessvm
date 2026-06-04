import {
  ACTIVE_STATE,
  EXPIRED_STATE,
  ISSUED_STATE,
  REFRESH_TOKEN_HEADER,
  REUSE_DETECTED_STATE,
  ROTATED_STATE,
  activateToken,
  createLifecycleStateCode,
  detectRefreshTokenReuse,
  expireToken,
  isLifecycleStateCode,
  revokeToken,
  rotateRefreshToken,
  type RefreshTokenRecord,
} from "../src";

const issuedRefreshToken: RefreshTokenRecord<typeof ISSUED_STATE> = {
  tokenHeader: REFRESH_TOKEN_HEADER,
  tokenId: "rtok-001",
  familyId: "rfam-001",
  sessionId: "sess-001",
  rotationCounter: 0,
  state: ISSUED_STATE,
  issuedAt: 1_717_404_800,
  expiresAt: 1_717_491_200,
};

const activeRefreshToken = activateToken(issuedRefreshToken);
const expiredRefreshToken = expireToken(activeRefreshToken);
const revokedRefreshToken = revokeToken(activeRefreshToken, "manual-admin-revoke");
const rotation = rotateRefreshToken(
  activeRefreshToken,
  "rtok-002",
  1_717_405_100,
  1_717_491_500,
);
const reuseDetection = detectRefreshTokenReuse(
  rotation.predecessor,
  1_717_405_200,
);

const activeState: typeof ACTIVE_STATE = activeRefreshToken.state;
const expiredState: typeof EXPIRED_STATE = expiredRefreshToken.state;
const rotatedState: typeof ROTATED_STATE = rotation.predecessor.state;
const reuseDetectedState: typeof REUSE_DETECTED_STATE =
  reuseDetection.reusedToken.state;

void activeState;
void expiredState;
void revokedRefreshToken;
void rotatedState;
void reuseDetectedState;

// @ts-expect-error Only active refresh tokens may rotate.
rotateRefreshToken(issuedRefreshToken, "rtok-003", 1_717_405_300, 1_717_491_600);

// @ts-expect-error Reuse detection only applies to already rotated refresh tokens.
detectRefreshTokenReuse(activeRefreshToken, 1_717_405_400);

const lifecycleCode = createLifecycleStateCode("A", 1);

if (!isLifecycleStateCode(lifecycleCode)) {
  throw new Error("Lifecycle helpers should accept a valid A1 state code.");
}
