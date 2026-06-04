import {
  ACCESS_TTL_DEFAULT,
  ACCESS_TTL_MAX,
  ACCESS_MAC_ALG,
  REFRESH_MAC_ALG,
  REFRESH_SECRET_BYTES,
  REFRESH_TTL_DEFAULT,
  SESSION_SECRET_BYTES,
  capAccessTtl,
  createBindingInput,
  createBindingFromFingerprint,
  createBindingInputFromFingerprint,
  createAccessPolicy,
  createAccessTokenPayload,
  createRefreshPolicy,
  createRefreshTokenPayload,
  createTokenHeader,
  parseTokenHeader,
  splitSerializedToken,
  isSessionSecret,
  isRefreshSecret,
  type BindMac,
  type Mac,
  type MacKey,
  type AccessTokenPayload,
  type RefreshTokenPayload,
} from "../src";

const accessPayload: AccessTokenPayload = {
  su: "user-123",
  jt: "jti-123",
  ia: 1_717_404_800,
  ex: 1_717_405_700,
  sc: ["profile:read"],
};

const refreshPayload: RefreshTokenPayload = {
  su: "user-123",
  si: "session-123",
  jt: "jti-123",
  ia: 1_717_404_800,
  ex: 1_717_491_200,
  bh: "bind-hash",
};

const acceptsAccessToken = (_payload: AccessTokenPayload): void => {};

acceptsAccessToken(accessPayload);

// @ts-expect-error Refresh payloads must never flow into access-token APIs.
acceptsAccessToken(refreshPayload);

const invalidAccessPayload: AccessTokenPayload = {
  su: "user-123",
  jt: "jti-123",
  ia: 1_717_404_800,
  ex: 1_717_405_700,
  sc: ["profile:read"],
  // @ts-expect-error Access payloads must stay free of session metadata.
  sid: "session-123",
};

void invalidAccessPayload;

const accessPolicy = createAccessPolicy();
const refreshPolicy = createRefreshPolicy("r1");
const header = createTokenHeader("A", 2);
const parsedHeader = parseTokenHeader(header);
const tokenParts = splitSerializedToken("A1.payload.signature");
const accessClaims = createAccessTokenPayload({
  su: "user-123",
  jt: "jti-123",
  ia: 1_717_404_800,
  sc: ["profile:read"],
});
const cappedTtl = capAccessTtl(ACCESS_TTL_MAX + 300);
const macKey: MacKey = {
  alg: ACCESS_MAC_ALG,
  sec: new Uint8Array(SESSION_SECRET_BYTES),
};
const mac: Mac = {
  async sign() {
    return "sig";
  },
  async verify() {
    return true;
  },
};
const bindMac: BindMac = {
  async sign() {
    return "bind-hash";
  },
};
const bindingInput = createBindingInput({
  j24: "0123456789abcdefghijklmn",
  uag: "ua-string",
});
const bindingFromFingerprint = createBindingFromFingerprint({
  ua: "ua-hash",
  al: "en-us,en;q=0.9",
  ja: "771,4865-4866,0-11-10,29-23-24,0",
  ip: "203.0.113.0/24",
  br: "chrome",
  bv: "126",
  asn: "as15169",
});
const deterministicBinding = createBindingInputFromFingerprint({
  ua: "ua-hash",
  al: "en-us,en;q=0.9",
  ja: "771,4865-4866,0-11-10,29-23-24,0",
  ip: "203.0.113.0/24",
  br: "chrome",
  bv: "126",
  asn: "as15169",
});
const refreshClaims = createRefreshTokenPayload({
  su: "user-123",
  si: "session-123",
  jt: "jti-123",
  ia: 1_717_404_800,
  bh: "bind-hash",
});
const refreshSecret = new Uint8Array(REFRESH_SECRET_BYTES);

void mac;
void bindMac;

if (parsedHeader === null || tokenParts === null) {
  throw new Error("Token helpers should accept a valid A1 token shape.");
}

if (accessPolicy.ttl !== ACCESS_TTL_DEFAULT) {
  throw new Error("Access policy should default to a 15 minute TTL.");
}

if (cappedTtl !== ACCESS_TTL_MAX) {
  throw new Error("Access TTL should clamp to the 60 minute hard ceiling.");
}

if (!isSessionSecret(macKey.sec)) {
  throw new Error("Access token HMAC secrets should be exactly 128 bits.");
}

if (accessClaims.ex !== accessClaims.ia + ACCESS_TTL_DEFAULT) {
  throw new Error("Access payloads should compute expiry from the capped TTL.");
}

if (refreshPolicy.alg !== REFRESH_MAC_ALG) {
  throw new Error("Refresh policy should use the refresh MAC profile.");
}

if (refreshPolicy.ttl !== REFRESH_TTL_DEFAULT) {
  throw new Error("Refresh policy should keep the default refresh TTL.");
}

if (!isRefreshSecret(refreshSecret)) {
  throw new Error("Refresh token secrets should be at least 32 bytes.");
}

if (bindingInput !== "0123456789abcdefghijklmn.ua-string") {
  throw new Error("Binding input should join the j24 fingerprint and user agent.");
}

if (bindingFromFingerprint.uag !== "ua-hash") {
  throw new Error("Fingerprint bindings should retain the hashed user agent.");
}

if (
  deterministicBinding !==
  "ua-hash|en-us,en;q=0.9|771,4865-4866,0-11-10,29-23-24,0|203.0.113.0/24|chrome|126"
) {
  throw new Error("Fingerprint bindings should serialize in deterministic field order.");
}

if (refreshClaims.bh !== "bind-hash") {
  throw new Error("Refresh payloads should carry the binding hash.");
}
