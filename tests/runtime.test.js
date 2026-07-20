const test = require("node:test");
const assert = require("node:assert/strict");
const {
  ACTIVE_STATE,
  csr,
  csi,
  REUSE_DETECTED_STATE,
  REVOKED_STATE,
  adp,
  asn,
  fpx,
  rlp,
  stp,
  ssv,
  createStore,
  ajtRef,
  fidRef,
  rtkKey,
  rtkRef,
  sidRef,
  usrRef,
  xcg,
  ssnKey,
} = require("../dist");

class FakeKv {
  constructor() {
    this.rows = new Map();
    this.refs = new Map();
    this.lists = new Map();
  }

  async put(rows) {
    for (const row of rows) {
      this.rows.set(`${row.key.pk}:${row.key.sk}`, row.val);
    }
  }

  async get(key) {
    return this.rows.get(`${key.pk}:${key.sk}`) ?? null;
  }

  async del(rows) {
    for (const row of rows) {
      this.rows.delete(`${row.key.pk}:${row.key.sk}`);
    }
  }

  async bind(refs) {
    for (const ref of refs) {
      this.refs.set(ref.val, ref.key);

      if (ref.cardinality === "one") {
        this.lists.set(ref.val, [ref.key]);
        continue;
      }

      const items = this.lists.get(ref.val) ?? [];

      if (!items.some((item) => `${item.pk}:${item.sk}` === `${ref.key.pk}:${ref.key.sk}`)) {
        items.push(ref.key);
        this.lists.set(ref.val, items);
      }
    }
  }

  async read(val) {
    return this.refs.get(val) ?? null;
  }

  async list(val) {
    return this.lists.get(val) ?? [];
  }

  async drop(vals) {
    for (const val of vals) {
      this.refs.delete(val);
      this.lists.delete(val);
    }
  }
}

function createSvc(overrides = {}) {
  let seed = 1;
  const rng = {
    bytes(size) {
      const bytes = new Uint8Array(size);

      for (let index = 0; index < size; index += 1) {
        bytes[index] = (seed + index) % 256;
      }

      seed += 1;
      return bytes;
    },
  };

  return ssv(createStore(new FakeKv()), {
    iss: "sessvm",
    aud: "api",
    accessKey: {
      alg: "H1",
      sec: new Uint8Array(16).fill(1),
    },
    bindKey: new Uint8Array(32).fill(2),
    rng,
    fpp: rlp(),
    ...overrides,
  });
}

function createExchange(store, overrides = {}) {
  return xcg(store, {
    accessKey: {
      alg: "H1",
      sec: new Uint8Array(16).fill(1),
    },
    bindKey: new Uint8Array(32).fill(2),
    fpp: rlp(),
    ...overrides,
  });
}

function createRequest(
  ip = "203.0.113.42",
  ua = "Mozilla/5.0 Chrome/126.0 Example",
  asn = null,
) {
  return {
    headers: {
      get(name) {
        switch (name.toLowerCase()) {
          case "user-agent":
            return ua;
          case "accept-language":
            return "en-US,en;q=0.9";
          case "x-asn":
            return asn;
          default:
            return null;
        }
      },
    },
    ip,
    tls: {
      ja3: "771,4865-4866,0-11-10,29-23-24,0",
    },
  };
}

function createAsnExtractor() {
  const extractor = fpx();
  return {
    async extract(request) {
      const fingerprint = await extractor.extract(request);
      return asn(fingerprint, request.headers.get("x-asn"));
    },
  };
}

const bind = {
  j24: "0123456789abcdefghijklmn",
  uag: "ua-string",
};

test("csrf verifier accepts matching cookie and header tokens", () => {
  const direct = csi({
    cookie: "csrf-001",
    header: "csrf-001",
  });
  const request = csr({
    headers: {
      get(name) {
        switch (name.toLowerCase()) {
          case "cookie":
            return "csrf=csrf-001";
          case "x-csrf-token":
            return "csrf-001";
          default:
            return null;
        }
      },
    },
  });

  assert.equal(direct.ok, true);
  assert.equal(request.ok, true);
});

test("csrf verifier rejects mismatched tokens", () => {
  const out = csi({
    cookie: "csrf-001",
    header: "csrf-002",
  });

  assert.equal(out.ok, false);
  assert.equal(out.rsn, "csrf-mismatch");
});

test("SessionSvc.start stores a session and refresh token", async () => {
  const svc = createSvc();
  const out = await svc.start({
    sub: "user-001",
    did: "device-001",
    scp: ["profile:read"],
    now: 1_717_404_800,
    bind,
  });

  assert.ok(out.atk.includes("."));
  assert.ok(out.rtk.length >= 64);

  const hit = await svc.store.getSessionByRefreshToken({
    tk: out.rtk,
  });

  assert.ok(hit);
  assert.equal(hit.ssn.id, out.ssn.id);
  assert.equal(hit.rtk.st, "I1");
});

test("SessionSvc.rotate rotates refresh tokens and returns a new pair", async () => {
  const svc = createSvc();
  const started = await svc.start({
    sub: "user-001",
    did: "device-001",
    scp: ["profile:read"],
    now: 1_717_404_800,
    bind,
  });

  const rotated = await svc.rotate({
    tk: started.rtk,
    did: "device-001",
    now: 1_717_404_900,
    bind,
  });

  assert.equal(rotated.ok, true);
  assert.notEqual(rotated.out.rtk, started.rtk);

  const oldHit = await svc.store.getSessionByRefreshToken({
    tk: started.rtk,
  });
  const newHit = await svc.store.getSessionByRefreshToken({
    tk: rotated.out.rtk,
  });

  assert.ok(oldHit);
  assert.ok(newHit);
  assert.equal(oldHit.rtk.st, "O1");
  assert.equal(newHit.rtk.st, "I1");
  assert.equal((await svc.store.kv.list(sidRef(started.ssn.id))).length, 1);
  assert.equal((await svc.store.kv.list(fidRef(oldHit.rtk.fid))).length, 2);
  assert.equal((await svc.store.kv.list(usrRef(started.ssn.sub))).length, 1);
  assert.equal(await svc.store.kv.read(ajtRef(started.ssn.ajt)), null);
  assert.deepEqual(
    await svc.store.kv.read(ajtRef(rotated.out.ssn.ajt)),
    ssnKey(started.ssn.id),
  );
});

test("SessionSvc.rotate detects replay of a rotated token and revokes the family/session", async () => {
  const svc = createSvc();
  const started = await svc.start({
    sub: "user-001",
    did: "device-001",
    scp: ["profile:read"],
    now: 1_717_404_800,
    bind,
  });

  const rotated = await svc.rotate({
    tk: started.rtk,
    did: "device-001",
    now: 1_717_404_900,
    bind,
  });

  assert.equal(rotated.ok, true);

  const oldHit = await svc.store.getSessionByRefreshToken({ tk: started.rtk });
  const newHit = await svc.store.getSessionByRefreshToken({
    tk: rotated.out.rtk,
  });

  assert.ok(oldHit);
  assert.ok(newHit);

  const replay = await svc.rotate({
    tk: started.rtk,
    did: "device-001",
    now: 1_717_405_000,
    bind,
  });

  assert.equal(replay.ok, false);
  assert.equal(replay.rsn, "refresh-reuse-detected");

  const replayHit = await svc.store.getSessionByRefreshToken({
    tk: started.rtk,
  });
  const currentHit = await svc.store.getSessionByRefreshToken({
    tk: rotated.out.rtk,
  });

  assert.equal(replayHit, null);
  assert.equal(currentHit, null);

  const replayRow = await svc.store.kv.get(rtkKey(oldHit.rtk.id));
  const currentRow = await svc.store.kv.get(rtkKey(newHit.rtk.id));
  const sessionRow = await svc.store.kv.get(ssnKey(started.ssn.id));

  assert.equal(replayRow.st, REUSE_DETECTED_STATE);
  assert.equal(currentRow.st, REVOKED_STATE);
  assert.equal(sessionRow.st, REVOKED_STATE);
});

test("SessionStore rejects legacy refs that point at a newer current row", async () => {
  const svc = createSvc();
  const started = await svc.start({
    sub: "user-001",
    did: "device-001",
    scp: ["profile:read"],
    now: 1_717_404_800,
    bind,
  });
  const rotated = await svc.rotate({
    tk: started.rtk,
    did: "device-001",
    now: 1_717_404_900,
    bind,
  });

  assert.equal(rotated.ok, true);

  const current = await svc.store.getSessionByRefreshToken({
    tk: rotated.out.rtk,
  });
  assert.ok(current);

  await svc.store.kv.bind([
    {
      val: ajtRef(started.ssn.ajt),
      key: ssnKey(started.ssn.id),
      cardinality: "one",
    },
    {
      val: rtkRef(started.rtk),
      key: rtkKey(current.rtk.id),
      cardinality: "one",
    },
  ]);

  assert.equal(
    await svc.store.getSessionByAccessToken({ jt: started.ssn.ajt }),
    null,
  );
  assert.equal(
    await svc.store.getSessionByRefreshToken({ tk: started.rtk }),
    null,
  );
});

test("SessionSvc.rotate rejects binding mismatch", async () => {
  const svc = createSvc();
  const started = await svc.start({
    sub: "user-001",
    did: "device-001",
    scp: ["profile:read"],
    now: 1_717_404_800,
    bind,
  });

  const rotated = await svc.rotate({
    tk: started.rtk,
    did: "device-001",
    now: 1_717_404_900,
    bind: {
      j24: "different-j24",
      uag: "different-ua",
    },
  });

  assert.equal(rotated.ok, false);
  assert.equal(rotated.rsn, "binding-mismatch");

  const hit = await svc.store.getSessionByRefreshToken({
    tk: started.rtk,
  });

  assert.ok(hit);
  assert.equal(hit.rtk.st, "I1");
});

test("SessionSvc.rotate returns a fingerprint verdict on policy-driven mismatches", async () => {
  const svc = createSvc({
    fp: createAsnExtractor(),
    risk: "RELAXED",
  });
  const started = await svc.start({
    sub: "user-001",
    did: "device-001",
    scp: ["profile:read"],
    now: 1_717_404_800,
    req: createRequest("203.0.113.42", "Mozilla/5.0 Chrome/126.0 Example", "as15169"),
  });

  const rotated = await svc.rotate({
    tk: started.rtk,
    did: "device-001",
    now: 1_717_404_900,
    req: {
      headers: {
        get(name) {
          switch (name.toLowerCase()) {
            case "user-agent":
              return "Mozilla/5.0 Firefox/127.0 Example";
            case "accept-language":
              return "fr-FR,fr;q=0.8";
            case "x-asn":
              return "as13335";
            default:
              return null;
          }
        },
      },
      ip: "198.51.100.10",
      tls: {
        ja3: null,
      },
    },
  });

  assert.equal(rotated.ok, false);
  assert.equal(rotated.rsn, "binding-mismatch");
  assert.ok(rotated.verdict);
  assert.equal(rotated.verdict.mode, "RELAXED");
});

test("SessionSvc.rotate rejects revoked-token rotation attempts", async () => {
  const svc = createSvc();
  const started = await svc.start({
    sub: "user-001",
    did: "device-001",
    scp: ["profile:read"],
    now: 1_717_404_800,
    bind,
  });

  await svc.revoke({
    sid: started.ssn.id,
    rsn: "manual",
    now: 1_717_404_850,
  });

  const rotated = await svc.rotate({
    tk: started.rtk,
    did: "device-001",
    now: 1_717_404_900,
    bind,
  });

  assert.equal(rotated.ok, false);
  assert.equal(rotated.rsn, "refresh-not-found");
});

test("SessionSvc can derive binding input from request fingerprints", async () => {
  const svc = createSvc();
  const extractor = fpx();
  const request = createRequest();
  const fingerprint = await extractor.extract(request);

  assert.ok(fingerprint.ua.length > 0);

  const started = await svc.start({
    sub: "user-001",
    did: "device-001",
    scp: ["profile:read"],
    now: 1_717_404_800,
    req: request,
  });

  const rotated = await svc.rotate({
    tk: started.rtk,
    did: "device-001",
    now: 1_717_404_900,
    req: createRequest("203.0.113.55"),
  });

  assert.equal(rotated.ok, true);
});

test("SessionSvc.rotate tolerates fingerprint drift allowed by policy", async () => {
  const svc = createSvc({
    fp: createAsnExtractor(),
    risk: "RELAXED",
  });
  const started = await svc.start({
    sub: "user-001",
    did: "device-001",
    scp: ["profile:read"],
    now: 1_717_404_800,
    req: createRequest("203.0.113.42", "Mozilla/5.0 Chrome/126.0 Example", "as15169"),
  });

  const rotated = await svc.rotate({
    tk: started.rtk,
    did: "device-001",
    now: 1_717_404_900,
    req: {
      headers: {
        get(name) {
          switch (name.toLowerCase()) {
            case "user-agent":
              return "Mozilla/5.0 Chrome/127.0 Example";
            case "accept-language":
              return "en-GB,en;q=0.8";
            case "x-asn":
              return "as15169";
            default:
              return null;
          }
        },
      },
      ip: "203.0.113.99",
      tls: {
        ja3: null,
      },
    },
  });

  assert.equal(rotated.ok, true);
});

test("SessionSvc.rotate enforces strict binding equality in STRICT mode", async () => {
  const svc = createSvc({
    fp: createAsnExtractor(),
    risk: "STRICT",
    fpp: stp(),
  });
  const started = await svc.start({
    sub: "user-001",
    did: "device-001",
    scp: ["profile:read"],
    now: 1_717_404_800,
    req: createRequest("203.0.113.42", "Mozilla/5.0 Chrome/126.0 Example", "as15169"),
  });

  const rotated = await svc.rotate({
    tk: started.rtk,
    did: "device-001",
    now: 1_717_404_900,
    req: createRequest("203.0.113.99", "Mozilla/5.0 Chrome/127.0 Example", "as15169"),
  });

  assert.equal(rotated.ok, false);
  assert.equal(rotated.rsn, "binding-mismatch");
});

test("SessionSvc.rotate tightens adaptive policy for stable users", async () => {
  const svc = createSvc({
    fp: createAsnExtractor(),
    risk: "ADAPTIVE",
    stable: true,
    fpp: adp(true),
  });
  const started = await svc.start({
    sub: "user-001",
    did: "device-001",
    scp: ["profile:read"],
    now: 1_717_404_800,
    req: createRequest("203.0.113.42", "Mozilla/5.0 Chrome/126.0 Example", "as15169"),
  });

  const rotated = await svc.rotate({
    tk: started.rtk,
    did: "device-001",
    now: 1_717_404_900,
    req: {
      headers: {
        get(name) {
          switch (name.toLowerCase()) {
            case "user-agent":
              return "Mozilla/5.0 Firefox/127.0 Example";
            case "accept-language":
              return "fr-FR,fr;q=0.8";
            case "x-asn":
              return "as13335";
            default:
              return null;
          }
        },
      },
      ip: "198.51.100.10",
      tls: {
        ja3: null,
      },
    },
  });

  assert.equal(rotated.ok, false);
  assert.equal(rotated.rsn, "binding-mismatch");
  assert.equal(rotated.verdict.mode, "ADAPTIVE");
});

test("SessionSvc.rotate revokes the full family after replay across multiple rotations", async () => {
  const svc = createSvc();
  const started = await svc.start({
    sub: "user-001",
    did: "device-001",
    scp: ["profile:read"],
    now: 1_717_404_800,
    bind,
  });

  const second = await svc.rotate({
    tk: started.rtk,
    did: "device-001",
    now: 1_717_404_900,
    bind,
  });
  assert.equal(second.ok, true);

  const third = await svc.rotate({
    tk: second.out.rtk,
    did: "device-001",
    now: 1_717_405_000,
    bind,
  });
  assert.equal(third.ok, true);

  const fourth = await svc.rotate({
    tk: third.out.rtk,
    did: "device-001",
    now: 1_717_405_100,
    bind,
  });
  assert.equal(fourth.ok, true);

  const replay = await svc.rotate({
    tk: second.out.rtk,
    did: "device-001",
    now: 1_717_405_200,
    bind,
  });

  assert.equal(replay.ok, false);
  assert.equal(replay.rsn, "refresh-reuse-detected");

  const firstHit = await svc.store.getSessionByRefreshToken({ tk: started.rtk });
  const secondHit = await svc.store.getSessionByRefreshToken({ tk: second.out.rtk });
  const thirdHit = await svc.store.getSessionByRefreshToken({ tk: third.out.rtk });
  const fourthHit = await svc.store.getSessionByRefreshToken({ tk: fourth.out.rtk });

  assert.equal(firstHit, null);
  assert.equal(secondHit, null);
  assert.equal(thirdHit, null);
  assert.equal(fourthHit, null);

  const sessionRow = await svc.store.kv.get(ssnKey(started.ssn.id));
  assert.equal(sessionRow.st, REVOKED_STATE);
});

test("SessionSvc.revoke revokes the stored session", async () => {
  const svc = createSvc();
  const started = await svc.start({
    sub: "user-001",
    did: "device-001",
    scp: ["profile:read"],
    now: 1_717_404_800,
    bind,
  });

  const revoked = await svc.revoke({
    sid: started.ssn.id,
    rsn: "manual",
    now: 1_717_405_100,
  });

  assert.equal(revoked, true);

  const session = await svc.store.kv.get(ssnKey(started.ssn.id));
  assert.ok(session);
  assert.equal(session.st, REVOKED_STATE);
});

test("SessionSvc.revoke removes access and refresh lookups for the whole family", async () => {
  const svc = createSvc();
  const started = await svc.start({
    sub: "user-001",
    did: "device-001",
    scp: ["profile:read"],
    now: 1_717_404_800,
    bind,
  });
  const second = await svc.rotate({
    tk: started.rtk,
    did: "device-001",
    now: 1_717_404_900,
    bind,
  });

  assert.equal(second.ok, true);

  const current = await svc.store.getSessionByRefreshToken({
    tk: second.out.rtk,
  });
  assert.ok(current);

  const revoked = await svc.revoke({
    sid: started.ssn.id,
    rsn: "manual",
    now: 1_717_405_000,
  });

  assert.equal(revoked, true);
  assert.equal(
    await svc.store.getSessionByRefreshToken({ tk: started.rtk }),
    null,
  );
  assert.equal(
    await svc.store.getSessionByRefreshToken({ tk: second.out.rtk }),
    null,
  );
  assert.equal((await svc.store.kv.list(fidRef(current.rtk.fid))).length, 0);
  assert.equal((await svc.store.kv.list(sidRef(started.ssn.id))).length, 0);
  assert.equal((await svc.store.kv.list(usrRef(started.ssn.sub))).length, 1);
});

test("SessionStore lists active sessions as device-scoped views", async () => {
  const store = createStore(new FakeKv());
  const svc = ssv(store, {
    iss: "sessvm",
    aud: "api",
    accessKey: {
      alg: "H1",
      sec: new Uint8Array(16).fill(1),
    },
    bindKey: new Uint8Array(32).fill(2),
  });

  await svc.start({
    sub: "user-001",
    did: "device-phone",
    dn: "Chrome on Pixel",
    loc: "New York",
    scp: ["profile:read"],
    now: 1_717_404_800,
    req: createRequest(),
  });
  await svc.start({
    sub: "user-001",
    did: "device-laptop",
    dn: "Firefox on Laptop",
    loc: "Lagos",
    scp: ["profile:read"],
    now: 1_717_404_900,
    req: createRequest("198.51.100.10", "Mozilla/5.0 Firefox/127.0 Example"),
  });

  const listed = await store.listActiveSessions({
    sub: "user-001",
  });

  assert.equal(listed.length, 2);
  assert.deepEqual(
    listed.map((item) => item.did),
    ["device-laptop", "device-phone"],
  );
  assert.equal(listed[0].dn, "Firefox on Laptop");
  assert.equal(listed[0].loc, "Lagos");
});

test("RefreshExchange refreshes an expired access token using server-side session state", async () => {
  const store = createStore(new FakeKv());
  const svc = ssv(store, {
    iss: "sessvm",
    aud: "api",
    accessKey: {
      alg: "H1",
      sec: new Uint8Array(16).fill(1),
    },
    bindKey: new Uint8Array(32).fill(2),
  });
  const started = await svc.start({
    sub: "user-001",
    did: "device-001",
    scp: ["profile:read"],
    now: 1_717_404_800,
    req: createRequest(),
  });
  const exchange = createExchange(store);

  const out = await exchange.run({
    atk: started.atk,
    did: "device-001",
    now: 1_717_405_800,
    req: createRequest(),
  });

  assert.equal(out.ok, true);
  assert.equal(out.refreshed, true);
  assert.ok(typeof out.atk === "string");
  assert.notEqual(out.atk, started.atk);
});

test("SessionSvc.exchange rejects access refresh from a different device uuid", async () => {
  const store = createStore(new FakeKv());
  const svc = ssv(store, {
    iss: "sessvm",
    aud: "api",
    accessKey: {
      alg: "H1",
      sec: new Uint8Array(16).fill(1),
    },
    bindKey: new Uint8Array(32).fill(2),
  });
  const started = await svc.start({
    sub: "user-001",
    did: "device-001",
    scp: ["profile:read"],
    now: 1_717_404_800,
    req: createRequest(),
  });

  const out = await svc.exchange({
    atk: started.atk,
    did: "device-002",
    now: 1_717_405_800,
    req: createRequest(),
  });

  assert.equal(out.ok, false);
  assert.equal(out.refreshed, false);
  assert.equal(out.rsn, "device-mismatch");
});

test("SessionSvc.exchange owns the server-side access refresh protocol", async () => {
  const store = createStore(new FakeKv());
  const svc = ssv(store, {
    iss: "sessvm",
    aud: "api",
    accessKey: {
      alg: "H1",
      sec: new Uint8Array(16).fill(1),
    },
    bindKey: new Uint8Array(32).fill(2),
  });
  const started = await svc.start({
    sub: "user-001",
    did: "device-001",
    scp: ["profile:read"],
    now: 1_717_404_800,
    req: createRequest(),
  });

  const out = await svc.exchange({
    atk: started.atk,
    did: "device-001",
    now: 1_717_405_800,
    req: createRequest(),
  });

  assert.equal(out.ok, true);
  assert.equal(out.refreshed, true);
  assert.ok(typeof out.atk === "string");
  assert.notEqual(out.atk, started.atk);
});

test("SessionSvc.exchange does not need a refresh token row", async () => {
  const kv = new FakeKv();
  const store = createStore(kv);
  const svc = ssv(store, {
    iss: "sessvm",
    aud: "api",
    accessKey: {
      alg: "H1",
      sec: new Uint8Array(16).fill(1),
    },
    bindKey: new Uint8Array(32).fill(2),
  });
  const started = await svc.start({
    sub: "user-001",
    did: "device-001",
    scp: ["profile:read"],
    now: 1_717_404_800,
    req: createRequest(),
  });
  const hit = await store.getSessionByRefreshToken({
    tk: started.rtk,
  });

  assert.ok(hit);

  await kv.del([
    {
      key: rtkKey(hit.rtk.id),
    },
  ]);
  await kv.drop([rtkRef(started.rtk), sidRef(started.ssn.id)]);

  const out = await svc.exchange({
    atk: started.atk,
    did: "device-001",
    now: 1_717_405_800,
    req: createRequest(),
  });

  assert.equal(out.ok, true);
  assert.equal(out.refreshed, true);
  assert.ok(typeof out.atk === "string");
});

test("RefreshExchange keeps a still-valid access token unchanged", async () => {
  const store = createStore(new FakeKv());
  const svc = ssv(store, {
    iss: "sessvm",
    aud: "api",
    accessKey: {
      alg: "H1",
      sec: new Uint8Array(16).fill(1),
    },
    bindKey: new Uint8Array(32).fill(2),
  });
  const started = await svc.start({
    sub: "user-001",
    did: "device-001",
    scp: ["profile:read"],
    now: 1_717_404_800,
    req: createRequest(),
  });
  const exchange = createExchange(store);

  const out = await exchange.run({
    atk: started.atk,
    did: "device-001",
    now: 1_717_404_900,
    req: createRequest(),
  });

  assert.equal(out.ok, true);
  assert.equal(out.refreshed, false);
  assert.equal(out.atk, started.atk);
});

test("RefreshExchange rejects revoked sessions", async () => {
  const store = createStore(new FakeKv());
  const svc = ssv(store, {
    iss: "sessvm",
    aud: "api",
    accessKey: {
      alg: "H1",
      sec: new Uint8Array(16).fill(1),
    },
    bindKey: new Uint8Array(32).fill(2),
  });
  const started = await svc.start({
    sub: "user-001",
    did: "device-001",
    scp: ["profile:read"],
    now: 1_717_404_800,
    req: createRequest(),
  });

  await svc.revoke({
    sid: started.ssn.id,
    rsn: "manual",
    now: 1_717_405_000,
  });

  const exchange = createExchange(store);
  const out = await exchange.run({
    atk: started.atk,
    did: "device-001",
    now: 1_717_405_800,
    req: createRequest(),
  });

  assert.equal(out.ok, false);
  assert.equal(out.refreshed, false);
  assert.equal(out.rsn, "session-not-found");
});

test("SessionSvc.rotate rejects and unlinks expired refresh state", async () => {
  const svc = createSvc();
  const started = await svc.start({
    sub: "user-001",
    did: "device-001",
    scp: ["profile:read"],
    now: 1_717_404_800,
    bind,
  });

  const rotated = await svc.rotate({
    tk: started.rtk,
    did: "device-001",
    now: started.ssn.exp,
    bind,
  });

  assert.equal(rotated.ok, false);
  assert.equal(rotated.rsn, "refresh-not-active");
  assert.equal(
    await svc.store.getSessionByRefreshToken({ tk: started.rtk }),
    null,
  );
  assert.equal(
    await svc.store.getSessionByAccessToken({ jt: started.ssn.ajt }),
    null,
  );
});
