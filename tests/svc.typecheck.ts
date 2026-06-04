import {
  ACTIVE_STATE,
  ACCESS_MAC_ALG,
  adp,
  createMemStore,
  createStore,
  rlp,
  ssv,
  stp,
  xcg,
  type DelRec,
  type Key,
  type Kv,
  type Ref,
  type Rtk,
  type SetRec,
  type Ssn,
  nodeBindMac,
  nodeMac,
  signAccessToken,
  verifyAccessToken,
  type AccessPolicy,
  type MacKey,
} from "../src";

const accessKey: MacKey = {
  alg: ACCESS_MAC_ALG,
  sec: new Uint8Array(16).fill(1),
};

const svc = ssv(createMemStore({ mode: "dev" }), {
  iss: "sessvm",
  aud: "api",
  accessKey,
  bindKey: new Uint8Array(32).fill(2),
  fpp: rlp(),
  risk: "RELAXED",
  stable: false,
});
const exchange = xcg(createMemStore({ mode: "dev" }), {
  iss: "sessvm",
  aud: "api",
  accessKey,
  bindKey: new Uint8Array(32).fill(2),
  risk: "STRICT",
  fpp: stp(),
});
const adaptive = adp(true);

const rows = new Map<string, Ssn | Rtk>();
const refs = new Map<string, Key>();
const kv: Kv = {
  async put(items: readonly SetRec[]) {
    for (const item of items) {
      rows.set(`${item.key.pk}:${item.key.sk}`, item.val);
    }
  },
  async get(key: Key) {
    return rows.get(`${key.pk}:${key.sk}`) ?? null;
  },
  async del(items: readonly DelRec[]) {
    for (const item of items) {
      rows.delete(`${item.key.pk}:${item.key.sk}`);
    }
  },
  async bind(items: readonly Ref[]) {
    for (const item of items) {
      refs.set(item.val, item.key);
    }
  },
  async read(val: string) {
    return refs.get(val) ?? null;
  },
  async list(val: string) {
    const key = refs.get(val);
    return key === undefined ? [] : [key];
  },
  async drop(vals: readonly string[]) {
    for (const val of vals) {
      refs.delete(val);
    }
  },
};

void createStore(kv);
void nodeBindMac;
void exchange;
void adaptive;

async function run(): Promise<void> {
  const started = await svc.start({
    sub: "user-001",
    did: "device-001",
    scp: ["profile:read"],
    now: 1_717_404_800,
    bind: {
      j24: "0123456789abcdefghijklmn",
      uag: "ua-string",
    },
  });

  const rotated = await svc.rotate({
    tk: started.rtk,
    did: "device-001",
    now: 1_717_404_900,
    bind: {
      j24: "0123456789abcdefghijklmn",
      uag: "ua-string",
    },
  });

  if (!rotated.ok) {
    throw new Error("Session service should rotate a valid refresh token.");
  }

  const revoked = await svc.revoke({
    sid: rotated.out.ssn.id,
    rsn: "manual",
    now: 1_717_405_000,
  });

  if (!revoked) {
    throw new Error("Session service should revoke a stored session.");
  }

  const access = await signAccessToken(
    {
      su: "user-001",
      jt: "jti-001",
      ia: 1_717_404_800,
      ex: 1_717_405_700,
      sc: ["profile:read"],
    },
    accessKey,
    nodeMac,
  );

  const payload = await verifyAccessToken(
    access.tk,
    accessKey,
    nodeMac,
    {
      hd: "A1",
      alg: ACCESS_MAC_ALG,
      ttl: 900,
      max: 3600,
      sz: 16,
    } satisfies AccessPolicy,
  );

  if (payload === null || payload.su !== "user-001") {
    throw new Error("Access token verification should return the payload.");
  }

  const state = ACTIVE_STATE;
  void state;

  const requestStarted = await svc.start({
    sub: "user-002",
    did: "device-002",
    scp: ["profile:read"],
    now: 1_717_405_200,
    req: {
      headers: {
        get(name: string) {
          switch (name.toLowerCase()) {
            case "user-agent":
              return "Mozilla/5.0 Example";
            case "accept-language":
              return "en-US,en;q=0.9";
            default:
              return null;
          }
        },
      },
      ip: "203.0.113.42",
      tls: {
        ja3: "771,4865-4866,0-11-10,29-23-24,0",
      },
    },
  });

  const requestRotated = await svc.rotate({
    tk: requestStarted.rtk,
    did: "device-002",
    now: 1_717_405_300,
    req: {
      headers: {
        get(name: string) {
          switch (name.toLowerCase()) {
            case "user-agent":
              return "Mozilla/5.0 Example";
            case "accept-language":
              return "en-US,en;q=0.9";
            default:
              return null;
          }
        },
      },
      ip: "203.0.113.55",
      tls: {
        ja3: "771,4865-4866,0-11-10,29-23-24,0",
      },
    },
  });

  if (!requestRotated.ok) {
    throw new Error("Session service should derive binding input from a request.");
  }
}

void run();
