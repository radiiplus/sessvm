import {
  ACTIVE_STATE,
  ISSUED_STATE,
  REVOKED_STATE,
  ajtRef,
  createAccessExchangePlan,
  createRef,
  createFamilyRevokePlan,
  createRevokePlan,
  createRotatePlan,
  createSessionRef,
  createSessionPlan,
  isRtk,
  isSsn,
  mapRtk,
  pst,
  rtkKey,
  rtkRef,
  ssnKey,
  type CrtIn,
  type GetByAccessIn,
  type Kv,
  type Port,
  type RotIn,
  type Store,
  type Ssn,
} from "../src";

const ssn: Ssn = {
  id: "sess-001",
  sub: "user-001",
  did: "device-001",
  iss: "sessvm",
  aud: "api",
  scp: ["profile:read"],
  st: ACTIVE_STATE,
  iat: 1_717_404_800,
  exp: 1_717_491_200,
  rat: 1_717_404_900,
  la: 1_717_404_900,
  ajt: "jti-001",
  bh: "bind-001",
  fp: {
    ua: "ua-hash",
    al: "en-us,en;q=0.9",
    ja: "771,4865-4866-4867,0-11-10,29-23-24,0",
    ip: "203.0.113.0/24",
  },
};

const createIn: CrtIn = {
  ssn,
  rtk: {
    id: "rtok-001",
    tk: "lookup-001",
    fid: "fam-001",
    kid: "r1",
    hd: "R1",
    su: "user-001",
    sid: "sess-001",
    jt: "jti-001",
    bh: "bind-001",
    st: ISSUED_STATE,
    iat: 1_717_404_800,
    exp: 1_717_491_200,
    fp: {
      ua: "ua-hash",
      al: "en-us,en;q=0.9",
      ja: "771,4865-4866-4867,0-11-10,29-23-24,0",
      ip: "203.0.113.0/24",
    },
  },
};

const createPlan = createSessionPlan(createIn);
const revokePlan = createRevokePlan(
  ssn,
  {
    ...createIn.rtk,
    st: ACTIVE_STATE,
  },
  1_717_405_000,
  "admin-revoke",
);

const rotateIn: RotIn = {
  cur: {
    ...createIn.rtk,
    st: ACTIVE_STATE,
  },
  nxt: {
    ...createIn.rtk,
    id: "rtok-002",
    tk: "lookup-002",
    jt: "jti-002",
    st: ISSUED_STATE,
  },
  at: 1_717_405_100,
};

const rotatePlan = createRotatePlan(rotateIn, ssn);
const accessPlan = createAccessExchangePlan(
  ssn,
  {
    sid: ssn.id,
    ajt: "jti-002",
    at: 1_717_405_050,
  },
);
const familyPlan = createFamilyRevokePlan(
  ssn,
  [createIn.rtk],
  1_717_405_025,
  "family-revoke",
);
const refs = createRef(createIn.rtk);
const sessionRefs = createSessionRef(ssn);
const refVal = rtkRef(createIn.rtk.id);
const accessRefVal = ajtRef("jti-001");
const sessionKey = ssnKey(ssn.id);
const refreshKey = rtkKey(createIn.rtk.id);
const accessGetIn: GetByAccessIn = {
  jt: "jti-001",
};

void refs;
void sessionRefs;
void refVal;
void accessRefVal;
void sessionKey;
void refreshKey;
void accessGetIn;

const mapped = mapRtk({
  tokenHeader: "R1",
  tokenId: "rtok-003",
  familyId: "fam-001",
  sessionId: "sess-001",
  rotationCounter: 2,
  state: REVOKED_STATE,
  issuedAt: 1_717_404_800,
  expiresAt: 1_717_491_200,
  revokedReason: "reuse",
});

if (!isRtk(mapped)) {
  throw new Error("Mapped refresh token should produce an Rtk record.");
}

if (!isSsn(createPlan.ssn)) {
  throw new Error("Session plan should expose an Ssn record.");
}

if (rotatePlan.nxt.st !== ISSUED_STATE) {
  throw new Error("Rotation should issue a new refresh token in I1 state.");
}

if (revokePlan.rtk.st !== REVOKED_STATE) {
  throw new Error("Revoke plan should mark the refresh token as V1.");
}

if (accessPlan.ssn.ajt !== "jti-002") {
  throw new Error("Access exchange should update the session's latest access jti.");
}

if (familyPlan.ssn.st !== REVOKED_STATE) {
  throw new Error("Family revoke should revoke the session state.");
}

const kv: Kv = {
  async put() {},
  async get() {
    return null;
  },
  async del() {},
  async bind() {},
  async read() {
    return null;
  },
  async list() {
    return [];
  },
  async drop() {},
};

const port: Port = kv;
const portStore = pst(port);

const store: Store = {
  kv,
  async createSession(input) {
    return createSessionPlan(input);
  },
  async getSessionByRefreshToken() {
    return null;
  },
  async getSessionByAccessToken() {
    return null;
  },
  async getSessionByDevice() {
    return null;
  },
  async listActiveSessions() {
    return [];
  },
  async revokeSession() {
    return null;
  },
  async revokeSessionFamily() {
    return null;
  },
  async revokeRefreshFamily() {
    return null;
  },
  async exchangeAccessToken() {
    return null;
  },
  async rotateRefreshToken(input) {
    return createRotatePlan(input, ssn);
  },
};

void portStore;
void store;
