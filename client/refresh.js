"use strict";

const DEFAULT_ACCESS_COOKIE = "atk";
const DEFAULT_DEVICE_COOKIE = "did";
const DEFAULT_CSRF_COOKIE = "csrf";
const DEVICE_HEADER = "X-Session-Device";
const CSRF_HEADER = "X-CSRF-Token";

function getDocumentCookie() {
  return typeof document === "undefined" ? "" : document.cookie;
}

function readCookie(name, cookieSource = getDocumentCookie()) {
  const target = `${name}=`;
  const parts = cookieSource.split(";");

  for (const raw of parts) {
    const part = raw.trim();

    if (part.startsWith(target)) {
      return decodeURIComponent(part.slice(target.length));
    }
  }

  return null;
}

function writeCookie(name, value, options = {}) {
  if (typeof document === "undefined") {
    return;
  }

  const {
    maxAge,
    path = "/",
    sameSite = "Strict",
    secure = true,
  } = options;
  const parts = [
    `${name}=${encodeURIComponent(value)}`,
    `Path=${path}`,
    `SameSite=${sameSite}`,
  ];

  if (secure) {
    parts.push("Secure");
  }

  if (typeof maxAge === "number") {
    parts.push(`Max-Age=${maxAge}`);
  }

  document.cookie = parts.join("; ");
}

function randomHex(bytes) {
  const data = new Uint8Array(bytes);
  const cryptoImpl = globalThis.crypto;

  if (cryptoImpl?.getRandomValues) {
    cryptoImpl.getRandomValues(data);
  } else {
    for (let index = 0; index < data.length; index += 1) {
      data[index] = Math.floor(Math.random() * 256);
    }
  }

  return [...data]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function createDeviceId() {
  if (globalThis.crypto?.randomUUID) {
    return globalThis.crypto.randomUUID();
  }

  return `did-${randomHex(16)}`;
}

function bearer(atk) {
  return `Bearer ${atk}`;
}

function normalizeHeaders(headers) {
  if (headers instanceof Headers) {
    return new Headers(headers);
  }

  return new Headers(headers ?? {});
}

function safeJson(response) {
  const contentType = response.headers?.get?.("content-type") ?? "";

  if (!contentType.toLowerCase().includes("application/json")) {
    return Promise.resolve(null);
  }

  return response.json().catch(() => null);
}

export function sc(options = {}) {
  const {
    ac = DEFAULT_ACCESS_COOKIE,
    cc = DEFAULT_CSRF_COOKIE,
    dc = DEFAULT_DEVICE_COOKIE,
    aa = 900,
    ca = 7_200,
    da = 31_536_000,
    ep = "/auth/refresh",
    ft = globalThis.fetch,
    se = true,
    ss = "Strict",
  } = options;

  function getAccessToken() {
    return readCookie(ac);
  }

  function setAccessToken(atk, maxAge = aa) {
    writeCookie(ac, atk, {
      maxAge,
      sameSite: ss,
      secure: se,
    });
  }

  function getDeviceId() {
    const existing = readCookie(dc);

    if (existing !== null && existing.length > 0) {
      return existing;
    }

    const next = createDeviceId();
    writeCookie(dc, next, {
      maxAge: da,
      sameSite: ss,
      secure: se,
    });
    return next;
  }

  function getCsrfToken() {
    const existing = readCookie(cc);

    if (existing !== null && existing.length > 0) {
      return existing;
    }

    const next = randomHex(32);
    writeCookie(cc, next, {
      maxAge: ca,
      sameSite: ss,
      secure: se,
    });
    return next;
  }

  function authHeaders(input = {}) {
    const atk = input.atk ?? getAccessToken();
    const csrf = input.csrf ?? getCsrfToken();
    const did = input.did ?? getDeviceId();
    const headers = normalizeHeaders(input.headers);

    if (atk !== null && atk.length > 0) {
      headers.set("Authorization", bearer(atk));
    }

    headers.set(DEVICE_HEADER, did);
    headers.set(CSRF_HEADER, csrf);
    return headers;
  }

  async function refresh(input = {}) {
    if (typeof ft !== "function") {
      throw new Error("A fetch implementation is required.");
    }

    const atk = input.atk ?? getAccessToken();
    const did = input.did ?? getDeviceId();

    if (atk === null || atk.length === 0) {
      return {
        ok: false,
        refreshed: false,
        atk: null,
        sid: null,
        rsn: "missing-access-cookie",
      };
    }

    let response;

    try {
      response = await ft(input.ep ?? ep, {
        method: "POST",
        credentials: "include",
        headers: authHeaders({
          atk,
          did,
          headers: {
            "Content-Type": "application/json",
          },
        }),
        body: JSON.stringify({
          did,
        }),
      });
    } catch {
      return {
        ok: false,
        refreshed: false,
        atk: null,
        sid: null,
        rsn: "network-error",
      };
    }

    const payload = await safeJson(response);

    if (!response.ok) {
      return payload ?? {
        ok: false,
        refreshed: false,
        atk: null,
        sid: null,
        rsn: "refresh-http-error",
        status: response.status,
      };
    }

    if (payload?.ok && payload?.refreshed === true && typeof payload.atk === "string") {
      setAccessToken(payload.atk, input.aa ?? aa);
    }

    return payload ?? {
      ok: false,
      refreshed: false,
      atk: null,
      sid: null,
      rsn: "invalid-refresh-response",
    };
  }

  function http(input = {}) {
    return authHeaders(input);
  }

  async function request(url, input = {}) {
    if (typeof ft !== "function") {
      throw new Error("A fetch implementation is required.");
    }

    return ft(url, {
      ...input,
      credentials: input.credentials ?? "include",
      headers: authHeaders({
        headers: input.headers,
        atk: input.atk,
        csrf: input.csrf,
        did: input.did,
      }),
    });
  }

  function graphql(input = {}) {
    const headers = authHeaders(input);

    return {
      headers,
      fetchOptions: {
        headers,
        credentials: "include",
      },
    };
  }

  async function gql(endpointUrl, input = {}) {
    const headers = authHeaders({
      headers: {
        "Content-Type": "application/json",
        ...(input.headers ?? {}),
      },
      atk: input.atk,
      csrf: input.csrf,
      did: input.did,
    });

    return request(endpointUrl, {
      method: "POST",
      headers,
      body: JSON.stringify({
        query: input.query,
        ...(input.variables !== undefined ? { variables: input.variables } : {}),
        ...(input.operationName !== undefined ? { operationName: input.operationName } : {}),
      }),
    });
  }

  function ws(input = {}) {
    const atk = input.atk ?? getAccessToken();
    const did = input.did ?? getDeviceId();
    const token = atk === null ? "" : atk;

    return {
      did,
      connectionParams: {
        Authorization: token.length > 0 ? bearer(token) : "",
        [DEVICE_HEADER]: did,
      },
      protocols: token.length > 0
        ? [`sessvm.did.${encodeURIComponent(did)}`, `sessvm.atk.${encodeURIComponent(token)}`]
        : [`sessvm.did.${encodeURIComponent(did)}`],
    };
  }

  return {
    getAccessToken,
    setAccessToken,
    getCsrfToken,
    getDeviceId,
    authHeaders,
    refresh,
    http,
    request,
    graphql,
    gql,
    ws,
  };
}

export async function rf(options = {}) {
  return sc(options).refresh(options);
}
