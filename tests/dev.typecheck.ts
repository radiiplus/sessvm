import {
  ACTIVE_STATE,
  ISSUED_STATE,
  createBindingHash,
  createMemStore,
  createRefreshPolicy,
  createRefreshValue,
  sidRef,
  verifyBindingHash,
  type BindMac,
  type CrtIn,
  type Rng,
  type Ssn,
  type Store,
} from "../src";

const rng: Rng = {
  bytes(size) {
    return new Uint8Array(size).fill(7);
  },
};

const bindMac: BindMac = {
  async sign(data) {
    return `mac:${data}`;
  },
};

const refreshPolicy = createRefreshPolicy("r1");
const refreshValue = createRefreshValue(refreshPolicy, rng);
const memStore: Store = createMemStore({
  mode: "dev",
});

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
    ja: "771,4865-4866,0-11-10,29-23-24,0",
    ip: "203.0.113.0/24",
  },
};

const createIn: CrtIn = {
  ssn,
  rtk: {
    id: "rtok-001",
    tk: refreshValue.val,
    fid: "fam-001",
    kid: refreshValue.kid,
    hd: refreshValue.hd,
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
      ja: "771,4865-4866,0-11-10,29-23-24,0",
      ip: "203.0.113.0/24",
    },
  },
};

void memStore.createSession(createIn);
void memStore.getSessionByRefreshToken({
  tk: refreshValue.val,
});
void memStore.revokeSession({
  sid: "sess-001",
  rsn: "manual",
  at: 1_717_405_000,
});
void sidRef("sess-001");

async function runBindingChecks(): Promise<void> {
  const hash = await createBindingHash(
    {
      j24: "0123456789abcdefghijklmn",
      uag: "ua-string",
    },
    new Uint8Array(32),
    bindMac,
  );

  const ok = await verifyBindingHash(
    hash,
    {
      j24: "0123456789abcdefghijklmn",
      uag: "ua-string",
    },
    new Uint8Array(32),
    bindMac,
  );

  if (!ok) {
    throw new Error("Binding hash verification should accept a matching hash.");
  }
}

void runBindingChecks();
