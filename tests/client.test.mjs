import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { createRequire } from "node:module";
import { connect } from "node:net";
import { sc, rf } from "../client/refresh.js";

const require = createRequire(import.meta.url);
const {
  csr,
  createStore,
  SqlKv,
  ssv,
} = require("../dist");

function installDocument(cookie = "") {
  const jar = new Map();

  for (const part of cookie.split(";")) {
    const trimmed = part.trim();

    if (trimmed.length === 0) {
      continue;
    }

    const [name, ...valueParts] = trimmed.split("=");
    jar.set(name, valueParts.join("="));
  }

  globalThis.document = {
    get cookie() {
      return [...jar.entries()]
        .map(([name, value]) => `${name}=${value}`)
        .join("; ");
    },
    set cookie(value) {
      const [pair] = value.split(";");
      const [name, ...valueParts] = pair.split("=");
      jar.set(name, valueParts.join("="));
    },
  };

  return jar;
}

test("client refresh sends bearer, device uuid, and csrf expected by backend", async () => {
  installDocument("atk=A2.token.sig; did=device-001; csrf=csrf-001");
  let observed = null;
  const client = sc({
    ft: async (url, init) => {
      observed = {
        url,
        init,
      };

      return new Response(
        JSON.stringify({
          ok: true,
          refreshed: true,
          atk: "A2.next.sig",
          sid: "sid-001",
        }),
        {
          status: 200,
          headers: {
            "content-type": "application/json",
          },
        },
      );
    },
    se: false,
  });

  const out = await client.refresh();

  assert.equal(out.ok, true);
  assert.equal(out.refreshed, true);
  assert.equal(observed.url, "/auth/refresh");
  assert.equal(observed.init.headers.get("Authorization"), "Bearer A2.token.sig");
  assert.equal(observed.init.headers.get("X-Session-Device"), "device-001");
  assert.equal(observed.init.headers.get("X-CSRF-Token"), "csrf-001");
  assert.equal(observed.init.body, JSON.stringify({ did: "device-001" }));
  assert.match(globalThis.document.cookie, /atk=A2\.next\.sig/);
});

test("client exposes auth material for http, graphql, and websocket flows", () => {
  installDocument("atk=A2.token.sig; did=device-001; csrf=csrf-001");
  const client = sc({
    se: false,
  });

  const http = client.http();
  const gql = client.graphql();
  const ws = client.ws();

  assert.equal(http.get("Authorization"), "Bearer A2.token.sig");
  assert.equal(http.get("X-Session-Device"), "device-001");
  assert.equal(http.get("X-CSRF-Token"), "csrf-001");
  assert.equal(gql.headers.get("Authorization"), "Bearer A2.token.sig");
  assert.equal(gql.headers.get("X-CSRF-Token"), "csrf-001");
  assert.equal(gql.fetchOptions.credentials, "include");
  assert.equal(ws.connectionParams.Authorization, "Bearer A2.token.sig");
  assert.equal(ws.connectionParams["X-Session-Device"], "device-001");
  assert.ok(ws.protocols.some((item) => item.startsWith("sessvm.did.")));
  assert.equal("query" in ws, false);
});

test("client request helper sends auth over plain http fetch", async () => {
  installDocument("atk=A2.token.sig; did=device-001; csrf=csrf-001");
  let observed = null;
  const client = sc({
    ft: async (url, init) => {
      observed = {
        url,
        init,
      };

      return new Response("ok");
    },
    se: false,
  });

  await client.request("/api/profile", {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      name: "Ada",
    }),
  });

  assert.equal(observed.url, "/api/profile");
  assert.equal(observed.init.method, "PATCH");
  assert.equal(observed.init.credentials, "include");
  assert.equal(observed.init.headers.get("Authorization"), "Bearer A2.token.sig");
  assert.equal(observed.init.headers.get("X-Session-Device"), "device-001");
  assert.equal(observed.init.headers.get("X-CSRF-Token"), "csrf-001");
  assert.equal(observed.init.headers.get("Content-Type"), "application/json");
});

test("client gql helper sends auth over graphql http", async () => {
  installDocument("atk=A2.token.sig; did=device-001; csrf=csrf-001");
  let observed = null;
  const client = sc({
    ft: async (url, init) => {
      observed = {
        url,
        init,
      };

      return new Response(
        JSON.stringify({
          data: {
            me: {
              id: "user-001",
            },
          },
        }),
        {
          headers: {
            "content-type": "application/json",
          },
        },
      );
    },
    se: false,
  });

  await client.gql("/graphql", {
    query: "query Me { me { id } }",
    variables: {
      limit: 1,
    },
    operationName: "Me",
  });

  assert.equal(observed.url, "/graphql");
  assert.equal(observed.init.method, "POST");
  assert.equal(observed.init.headers.get("Authorization"), "Bearer A2.token.sig");
  assert.equal(observed.init.headers.get("X-Session-Device"), "device-001");
  assert.equal(observed.init.headers.get("X-CSRF-Token"), "csrf-001");
  assert.equal(observed.init.headers.get("Content-Type"), "application/json");
  assert.deepEqual(JSON.parse(observed.init.body), {
    query: "query Me { me { id } }",
    variables: {
      limit: 1,
    },
    operationName: "Me",
  });
});

test("rf preserves the legacy entry point", async () => {
  installDocument("atk=A2.token.sig; did=device-001");

  const out = await rf({
    ft: async () => new Response(
      JSON.stringify({
        ok: true,
        refreshed: false,
        atk: "A2.token.sig",
        sid: "sid-001",
      }),
      {
        status: 200,
        headers: {
          "content-type": "application/json",
        },
      },
    ),
    se: false,
  });

  assert.equal(out.ok, true);
  assert.equal(out.refreshed, false);
});

function headerGetter(headers) {
  return {
    get(name) {
      const value = headers[name.toLowerCase()];

      if (Array.isArray(value)) {
        return value.join(", ");
      }

      return value ?? null;
    },
  };
}

function readBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];

    request.on("data", (chunk) => {
      chunks.push(chunk);
    });
    request.on("end", () => {
      resolve(Buffer.concat(chunks).toString("utf8"));
    });
    request.on("error", reject);
  });
}

function sendJson(response, status, payload) {
  response.writeHead(status, {
    "content-type": "application/json",
  });
  response.end(JSON.stringify(payload));
}

class E2eKv {
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

function listen(server) {
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      resolve(`http://127.0.0.1:${address.port}`);
    });
  });
}

function wsAccept(key) {
  return createHash("sha1")
    .update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`, "binary")
    .digest("base64");
}

function wsHandshake(port, protocols) {
  return new Promise((resolve, reject) => {
    const socket = connect(port, "127.0.0.1");
    let data = "";

    socket.on("connect", () => {
      socket.write([
        "GET /socket HTTP/1.1",
        "Host: 127.0.0.1",
        "Upgrade: websocket",
        "Connection: Upgrade",
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
        "Sec-WebSocket-Version: 13",
        `Sec-WebSocket-Protocol: ${protocols.join(", ")}`,
        "",
        "",
      ].join("\r\n"));
    });
    socket.on("data", (chunk) => {
      data += chunk.toString("utf8");

      if (data.includes("\r\n\r\n")) {
        socket.end();
        resolve(data);
      }
    });
    socket.on("error", reject);
  });
}

test("client refresh works end-to-end through a real HTTP endpoint", async () => {
  const store = createStore(new E2eKv());
  const svc = ssv(store, {
    iss: "sessvm",
    aud: "api",
    accessKey: {
      alg: "H1",
      sec: new Uint8Array(16).fill(1),
    },
    bindKey: new Uint8Array(32).fill(2),
  });
  const requestLike = {
    headers: {
      get(name) {
        switch (name.toLowerCase()) {
          case "user-agent":
            return "Mozilla/5.0 Chrome/126.0 Example";
          case "accept-language":
            return "en-US,en;q=0.9";
          default:
            return null;
        }
      },
    },
    ip: "203.0.113.42",
  };
  const started = await svc.start({
    sub: "user-001",
    did: "device-001",
    scp: ["profile:read"],
    now: 1_717_404_800,
    req: requestLike,
  });
  const server = createServer(async (request, response) => {
    if (request.method !== "POST" || request.url !== "/auth/refresh") {
      sendJson(response, 404, {
        ok: false,
        rsn: "not-found",
      });
      return;
    }

    const headers = headerGetter(request.headers);
    const csrf = csr({
      headers,
      ip: request.socket.remoteAddress,
    });

    if (!csrf.ok) {
      sendJson(response, 403, {
        ok: false,
        refreshed: false,
        atk: null,
        sid: null,
        rsn: csrf.rsn,
      });
      return;
    }

    const rawBody = await readBody(request);
    const body = JSON.parse(rawBody);
    const auth = headers.get("authorization") ?? "";
    const match = auth.match(/^Bearer\s+(.+)$/i);

    if (match === null) {
      sendJson(response, 401, {
        ok: false,
        refreshed: false,
        atk: null,
        sid: null,
        rsn: "missing-bearer",
      });
      return;
    }

    const out = await svc.exchange({
      atk: match[1],
      did: headers.get("x-session-device") ?? body.did,
      now: 1_717_405_800,
      req: {
        headers,
        ip: request.socket.remoteAddress,
      },
    });

    sendJson(response, out.ok ? 200 : 401, out);
  });
  const baseUrl = await listen(server);

  try {
    installDocument(`atk=${encodeURIComponent(started.atk)}; did=device-001; csrf=csrf-001`);
    const client = sc({
      ep: `${baseUrl}/auth/refresh`,
      ft: (url, init) => {
        const headers = new Headers(init.headers);
        headers.set("Cookie", globalThis.document.cookie);
        headers.set("User-Agent", "Mozilla/5.0 Chrome/126.0 Example");
        headers.set("Accept-Language", "en-US,en;q=0.9");
        return fetch(url, {
          ...init,
          headers,
        });
      },
      se: false,
    });

    const out = await client.refresh();

    assert.equal(out.ok, true);
    assert.equal(out.refreshed, true);
    assert.ok(typeof out.atk === "string");
    assert.notEqual(out.atk, started.atk);
    assert.match(globalThis.document.cookie, /atk=A1\./);
  } finally {
    await new Promise((resolve, reject) => {
      server.close((error) => {
        if (error) {
          reject(error);
          return;
        }

        resolve();
      });
    });
  }
});

test("client gql works end-to-end through a real graphql-over-http endpoint", async () => {
  const server = createServer(async (request, response) => {
    const headers = headerGetter(request.headers);

    if (request.method !== "POST" || request.url !== "/graphql") {
      sendJson(response, 404, {
        errors: [{ message: "not-found" }],
      });
      return;
    }

    const csrf = csr({
      headers,
    });
    const auth = headers.get("authorization");
    const did = headers.get("x-session-device");
    const body = JSON.parse(await readBody(request));

    if (!csrf.ok || auth !== "Bearer A2.token.sig" || did !== "device-001") {
      sendJson(response, 401, {
        errors: [{ message: "unauthorized" }],
      });
      return;
    }

    sendJson(response, 200, {
      data: {
        me: {
          id: "user-001",
          op: body.operationName,
        },
      },
    });
  });
  const baseUrl = await listen(server);

  try {
    installDocument("atk=A2.token.sig; did=device-001; csrf=csrf-001");
    const client = sc({
      ft: (url, init) => {
        const headers = new Headers(init.headers);
        headers.set("Cookie", globalThis.document.cookie);
        return fetch(url, {
          ...init,
          headers,
        });
      },
      se: false,
    });
    const response = await client.gql(`${baseUrl}/graphql`, {
      query: "query Me { me { id op } }",
      operationName: "Me",
    });
    const payload = await response.json();

    assert.equal(response.ok, true);
    assert.equal(payload.data.me.id, "user-001");
    assert.equal(payload.data.me.op, "Me");
  } finally {
    await new Promise((resolve, reject) => {
      server.close((error) => {
        if (error) {
          reject(error);
          return;
        }

        resolve();
      });
    });
  }
});

test("client ws auth works end-to-end through websocket subprotocol handshake", async () => {
  installDocument("atk=A2.token.sig; did=device-001; csrf=csrf-001");
  const client = sc({
    se: false,
  });
  let observed = null;
  const server = createServer();

  server.on("upgrade", (request, socket) => {
    const protocols = String(request.headers["sec-websocket-protocol"] ?? "")
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean);
    const did = protocols
      .find((item) => item.startsWith("sessvm.did."))
      ?.slice("sessvm.did.".length);
    const atk = protocols
      .find((item) => item.startsWith("sessvm.atk."))
      ?.slice("sessvm.atk.".length);

    observed = {
      did: decodeURIComponent(did ?? ""),
      atk: decodeURIComponent(atk ?? ""),
    };

    socket.write([
      "HTTP/1.1 101 Switching Protocols",
      "Upgrade: websocket",
      "Connection: Upgrade",
      `Sec-WebSocket-Accept: ${wsAccept(String(request.headers["sec-websocket-key"]))}`,
      `Sec-WebSocket-Protocol: ${protocols[0]}`,
      "",
      "",
    ].join("\r\n"));
    socket.end();
  });

  const baseUrl = await listen(server);
  const port = Number(new URL(baseUrl).port);

  try {
    const response = await wsHandshake(port, client.ws().protocols);

    assert.match(response, /101 Switching Protocols/);
    assert.equal(observed.did, "device-001");
    assert.equal(observed.atk, "A2.token.sig");
  } finally {
    await new Promise((resolve, reject) => {
      server.close((error) => {
        if (error) {
          reject(error);
          return;
        }

        resolve();
      });
    });
  }
});

test("sqlite mini persistence works as a custom Port implementation", async () => {
  const kv = new SqlKv();
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

  try {
    const started = await svc.start({
      sub: "user-001",
      did: "device-001",
      scp: ["profile:read"],
      now: 1_717_404_800,
      req: {
        headers: {
          get(name) {
            switch (name.toLowerCase()) {
              case "user-agent":
                return "Mozilla/5.0 Chrome/126.0 Example";
              case "accept-language":
                return "en-US,en;q=0.9";
              default:
                return null;
            }
          },
        },
        ip: "203.0.113.42",
      },
    });
    const listed = await store.listActiveSessions({
      sub: "user-001",
    });
    const out = await svc.exchange({
      atk: started.atk,
      did: "device-001",
      now: 1_717_405_800,
      req: {
        headers: {
          get(name) {
            switch (name.toLowerCase()) {
              case "user-agent":
                return "Mozilla/5.0 Chrome/126.0 Example";
              case "accept-language":
                return "en-US,en;q=0.9";
              default:
                return null;
            }
          },
        },
        ip: "203.0.113.55",
      },
    });

    assert.equal(listed.length, 1);
    assert.equal(listed[0].did, "device-001");
    assert.equal(out.ok, true);
    assert.equal(out.refreshed, true);
  } finally {
    kv.close();
  }
});
