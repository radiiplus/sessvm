# sessvm

**Server-Owned Session Management for TypeScript**

`sessvm` is a lightweight, highly modular session-management library built around the **server-owned session refresh** paradigm. Instead of relying on long-lived, client-held refresh tokens, `sessvm` keeps session and refresh state securely on the server. Clients present a compact access token, device UUID, and CSRF token, and the server validates the request against stored session state to issue a fresh access token when allowed.

---

## 🌟 Key Features

- **Server-Owned Refresh**: Session state and rotation logic live entirely on the server, mitigating refresh token theft and replay attacks.
- **Compact Tokens**: Access tokens use a 2-byte type/version header (e.g., `A1` for Access v1) for efficient protocol routing.
- **Pluggable Persistence**: Database-agnostic. Interacts with a generic async `Kv` persistence port, allowing you to bring your own Redis, PostgreSQL, SQLite, or in-memory store.
- **Built-in Security**: Includes double-submit CSRF verification and robust request fingerprinting (User-Agent, JA3/TLS, IP masking) with strict, relaxed, or adaptive policies.
- **Multi-Transport Client**: First-class browser client helpers supporting standard HTTP, GraphQL-over-HTTP, and WebSocket authentication handshakes.
- **Type-Safe**: Comprehensive TypeScript support with strict type-level checks for token payloads, lifecycle states, and persistence contracts.

---

## 📦 Installation

```bash
npm install sessvm
# or
yarn add sessvm
# or
pnpm add sessvm
```

---

## 🏗️ Architecture & Naming Philosophy

`sessvm` intentionally uses concise naming in its public API to reduce boilerplate while maintaining clarity through context:
- `ssv(...)`: Creates the main session service.
- `xcg(...)`: Creates the exchange wrapper.
- `pst(...)`: Wraps a persistence port.
- `fpx()`, `fpp()`, `stp()`, `rlp()`, `adp()`, `asn(...)`: Handle fingerprinting and risk policies.
- Client config uses 2-character keys: `ep` (endpoint), `ft` (fetch), `se` (secure), `ac` (access cookie), `dc` (device cookie), `cc` (CSRF cookie).

Longer names are preserved only where required by external protocols (e.g., `headers`, `credentials`, `operationName`).

---

## 🚀 Quick Start & Use Cases

### 1. Server Setup & Initialization

Configure the session service with your secret, persistence layer, and fingerprinting policy.

```typescript
import { ssv, pst, fpp } from 'sessvm';
import { createMemStore } from 'sessvm/dev/mem'; // Use your own production store in real apps

// 1. Wrap your persistence layer
const store = pst(createMemStore());

// 2. Configure fingerprint policy (e.g., relaxed matching)
const fpPolicy = fpp({ mode: 'relaxed' });

// 3. Initialize the session service
const sessionService = ssv({
  secret: process.env.SESSION_SECRET!, // Must be >= 32 bytes
  store,
  fingerprintPolicy: fpPolicy,
});
```

### 2. Starting a Session (Login)

When a user successfully authenticates, start a session and return the access token and CSRF token to the client.

```typescript
import { dvc } from 'sessvm';

app.post('/login', async (req, res) => {
  // Authenticate user...
  const userId = 'user-123';
  const deviceId = req.headers['x-device-id'] || crypto.randomUUID();

  const session = await sessionService.start({
    sub: userId,
    did: deviceId,
    scp: ['read', 'write'],
    now: Date.now(),
    req: req, // Passed for automatic fingerprint extraction (IP, UA, etc.)
  });

  // Set cookies on the response
  res.cookie('access_token', session.accessToken, { httpOnly: true, secure: true, sameSite: 'strict' });
  res.cookie('device_id', deviceId, { httpOnly: true, secure: true, sameSite: 'strict' });
  res.cookie('csrf_token', session.csrfToken, { secure: true, sameSite: 'strict' });

  res.json({ success: true });
});
```

### 3. Exchanging / Refreshing an Access Token

The core of `sessvm`. The client sends the current (potentially expired) access token. The server validates it, checks the device and fingerprint, and returns a fresh token if valid.

```typescript
import { csi } from 'sessvm';

app.post('/api/refresh', async (req, res) => {
  // 1. Verify CSRF
  const csrfCheck = csi({ cookie: req.cookies.csrf_token, header: req.headers['x-csrf-token'] });
  if (!csrfCheck.valid) {
    return res.status(403).json({ error: 'CSRF validation failed', reason: csrfCheck.reason });
 is valid, returns it unchanged. 
  // If expired, generates a new jti, updates the session row, and returns a refreshed token.
  const exchangeResult = await sessionService.exchange({
    token: req.cookies.access_token,
    did: req.cookies.device_id,
    now: Date.now(),
    req: req, // For fingerprint validation
  });

  // Set the new access token cookie
  res.cookie('access_token', exchangeResult.accessToken, { httpOnly: true, secure: true, sameSite: 'strict' });
  
  res.json({ refreshed: exchangeResult.refreshed });
});
```

### 4. Revoking a Session (Logout)

```typescript
app.post('/logout', async (req, res) => {
  const token = req.cookies.access_token;
  
  await sessionService.revoke({
    token,
    now: Date.now(),
  });

  res.clearCookie('access_token');
  res.clearCookie('device_id');
  res.clearCookie('csrf_token');
  res.json({ success: true });
});
```

---

## Client Package Usage

The browser helper is published separately from the server library as `sessvm-client`.

```bash
npm install sessvm-client
```

The client package exposes compact names:

- `sc(options)` creates the client helper.
- `rf(options)` runs a one-shot refresh.

```javascript
import { sc, rf } from 'sessvm-client';

const auth = sc({
  ep: '/auth/refresh', // refresh endpoint
  ft: window.fetch,    // fetch implementation
  ac: 'atk',           // access-token cookie
  dc: 'did',           // device UUID cookie
  cc: 'csrf',          // CSRF cookie
  se: false,           // set true when using Secure cookies
  ss: 'Strict',        // SameSite value
});
```

### Refresh

`auth.refresh()` sends the backend contract:

- `Authorization: Bearer <access-token>`
- `X-Session-Device: <device-uuid>`
- `X-CSRF-Token: <csrf-token>`
- JSON body: `{ did }`

```javascript
const out = await auth.refresh();

if (out.ok && out.refreshed) {
  console.log('access token refreshed');
}
```

One-shot form:

```javascript
await rf({
  ep: '/auth/refresh',
  se: false,
});
```

### HTTP

Use `request(...)` when you want the helper to call `fetch` with auth headers attached.

```javascript
const response = await auth.request('/api/profile', {
  method: 'GET',
});
```

Use `http(...)` when another library only needs headers.

```javascript
fetch('/api/profile', {
  headers: auth.http(),
  credentials: 'include',
});
```

### GraphQL

Use `gql(...)` for GraphQL-over-HTTP.

```javascript
const response = await auth.gql('/graphql', {
  query: 'query Me { me { id } }',
  operationName: 'Me',
});
```

Use `graphql(...)` when a GraphQL client wants context/fetch options.

```javascript
const ctx = auth.graphql();
```

### WebSocket

Browsers cannot set arbitrary `Authorization` headers during the native WebSocket handshake. The helper returns auth material in WebSocket-compatible forms.

```javascript
const wsAuth = auth.ws();

const socket = new WebSocket(
  'ws://localhost:3000/socket',
  wsAuth.protocols,
);
```

For GraphQL subscriptions clients, prefer `connectionParams`:

```javascript
const wsAuth = auth.ws();
const connectionParams = wsAuth.connectionParams;
```

---

## 🗄️ Custom Persistence Integration

`sessvm` does not dictate your database. You implement a simple async `Kv` port, and `sessvm` handles the session logic.

```typescript
import { pst } from 'sessvm';

// Example: A minimal Redis-backed Kv port
const redisKvPort = {
  async put(key, value, ttl) { /* redis.set(key, value, 'EX', ttl) */ },
  async get(key) { /* return redis.get(key) */ },
  async del(key) { /* return redis.del(key) */ },
  async bind(refKey, targetKey) { /* redis.sadd(refKey, targetKey) */ },
  async read(refKey) { /* return redis.smembers(refKey) */ },
  async list(prefix) { /* return redis.keys(`${prefix}*`) */ },
  async drop() { /* clear all */ }
};

// Wrap it to create a high-level Store
const myStore = pst(redisKvPort);
```
*Note: `sessvm` includes a prototype SQLite implementation (`sessvm/dev/sql`) using Node's experimental `node:sqlite` to demonstrate durable storage capabilities.*

---

## 🛡️ Security & Fingerprinting

`sessvm` provides robust fingerprinting to detect suspicious session usage (e.g., token theft).

```typescript
import { fpx, stp, rlp, adp } from 'sessvm';

// Extract fingerprint from request
const fp = fpx(req);

// Compare fingerprints based on policy
const isMatch = stp(fp, storedFp);       // Strict: Exact match required
const isRelaxedMatch = rlp(fp, storedFp); // Relaxed: Allows minor browser updates
const isAdaptiveMatch = adp(fp, storedFp, true); // Adaptive: Learns stable attributes
```

---

## 🧪 Development & Testing

The project is heavily tested for runtime behavior, client integration, and TypeScript type safety.

```bash
# Install dependencies
npm install

# Run type checking (validates payload contracts, lifecycle states, and store interfaces)
npm run typecheck

# Run runtime and integration tests
npm test

# Build the distribution files
npm run build
```

**Test Coverage Includes:**
- Core session service (start, exchange, revoke, rotate)
- Refresh-token replay detection and family revocation
- Binding/fingerprint mismatch handling
- CSRF verification
- HTTP, GraphQL, and WebSocket E2E refresh flows
- SQLite persistence integration

---

## 🚦 Production Readiness Checklist

While the core logic, client contract, and helpers are production-ready, deploying `sessvm` requires app-specific decisions:

- [ ] **Persistence Layer**: Replace the dev/memory store with a robust, production-grade `Kv` implementation (e.g., Redis, PostgreSQL).
- [ ] **Key Rotation**: Implement a strategy for rotating the `SESSION_SECRET` without invalidating all active sessions.
- [ ] **Transport Policy**: Enforce HTTPS, `Secure` cookies, and strict `SameSite` attributes in your deployment environment.
- [ ] **WebSocket Policy**: Define how your WebSocket server validates the auth material provided by `sessClient.ws()`.
- [ ] **Monitoring & Auditing**: Hook into the `Ssv` lifecycle events to log suspicious activity (e.g., fingerprint mismatches, replay attempts).

---

## 📄 License

MIT License. See [LICENSE](LICENSE) for details.