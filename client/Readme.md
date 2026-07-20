# sessvm-client

**Browser Client for sessvm Session Management**

`sessvm-client` is the lightweight browser companion for the `sessvm` server-owned session protocol. It automates the complexities of session maintenance, including access token refreshing, CSRF token management, and device identity persistence.

Designed for modern TypeScript/JavaScript applications, it provides a unified interface for HTTP, GraphQL, and WebSocket authentication flows.

---

## 🌟 Features

- **Auto-Refresh**: Automatically detects expired sessions (401) and refreshes access tokens before retrying requests.
- **CSRF Protection**: Manages double-submit CSRF tokens automatically for state-changing requests.
- **Multi-Transport Support**:
  - **HTTP**: Wrapped `fetch` with session handling.
  - **GraphQL**: Built-in helper for GraphQL-over-HTTP.
  - **WebSocket**: Generates authentication material for WS handshakes.
- **Cookie Management**: Securely reads/writes access, device, and CSRF cookies.
- **Zero Configuration Defaults**: Sensible defaults for secure cookie settings (`Secure`, `SameSite`).

---

## 📦 Installation

```bash
npm install sessvm-client
# or
yarn add sessvm-client
# or
pnpm add sessvm-client
```

---

## 🚀 Quick Start

### 1. Initialize the Client

Create a session client instance with your backend's refresh endpoint and cookie configuration.

```javascript
import { sc } from 'sessvm-client';

const sessClient = sc({
  ep: '/api/session/refresh', // Refresh endpoint URL
  ft: window.fetch,           // Fetch implementation (defaults to window.fetch)
  
  // Cookie Names (must match server configuration)
  ac: 'access_token',         // Access token cookie
  dc: 'device_id',            // Device UUID cookie
  cc: 'csrf_token',           // CSRF token cookie
  
  // Security Settings
  se: true,                   // Secure flag (true for HTTPS)
  ss: 'strict',               // SameSite policy
});
```

### 2. Make an HTTP Request

Use `request()` instead of `fetch()`. It automatically includes cookies and headers. If the access token is expired, it refreshes silently and retries.

```javascript
async function loadData() {
  try {
    const response = await sessClient.request('/api/users/profile', {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    const data = await response.json();
    console.log('Profile:', data);
  } catch (error) {
    console.error('Request failed:', error);
  }
}
```

### 3. GraphQL Support

Send GraphQL queries with automatic session handling.

```javascript
async function getUserData() {
  const result = await sessClient.gql('/api/graphql', {
    query: `
      query GetCurrentUser {
        me {
          id
          email
          role
        }
      }
    `,
    operationName: 'GetCurrentUser',
    variables: {},
  });

  console.log('GraphQL Result:', result);
}
```

### 4. WebSocket Authentication

Generate the necessary authentication material for WebSocket connections. `sessvm` servers often require specific subprotocols or auth headers during the WS handshake.

```javascript
function connectWebSocket() {
  const auth = sessClient.ws();
  
  // auth.protocols contains the required subprotocol strings
  // auth.token contains the current access token for manual auth payloads
  const socket = new WebSocket('wss://api.example.com/live', auth.protocols);

  socket.addEventListener('open', () => {
    // Optional: Send token in first message if required by your WS protocol
    socket.send(JSON.stringify({
      type: 'auth',
      token: auth.token,
      csrf: auth.csrf
    }));
  });
}
```

---

## ⚙️ Configuration Options

The `sc` function accepts a configuration object. Short keys are used to minimize bundle size.

| Key | Description | Default |
| :--- | :--- | :--- |
| `ep` | **E**ndpoint **P**ath. URL for refreshing tokens. | `'/refresh'` |
| `ft` | **F**etch **T**ransport. Custom fetch implementation. | `window.fetch` |
| `ac` | **A**ccess **C**ookie name. | `'access_token'` |
| `dc` | **D**evice **C**ookie name. | `'device_id'` |
| `cc` | **C**SRF **C**ookie name. | `'csrf_token'` |
| `se` | **S**ecure flag. Forces HTTPS-only cookies. | `true` |
| `ss` | **S**ame**S**ite policy. (`'strict'`, `'lax'`, `'none'`) | `'strict'` |
| `aa` | **A**ccess **A**ge. Max-Age for access cookie (seconds). | `3600` |
| `ca` | **C**SRF **A**ge. Max-Age for CSRF cookie (seconds). | `3600` |
| `da` | **D**evice **A**ge. Max-Age for device cookie (seconds). | `31536000` (1 year) |

---

## 🔐 Cookie Requirements

For the client to function correctly, your `sessvm` server must set the following cookies upon login or refresh:

1.  **Access Token** (`access_token`): Contains the signed JWT/bearer token.
2.  **Device UUID** (`device_id`): Unique identifier for the client device.
3.  **CSRF Token** (`csrf_token`): Random string used for double-submit verification.

**Example Server Response (Set-Cookie):**
```http
Set-Cookie: access_token=A1...; HttpOnly; Secure; SameSite=Strict; Path=/
Set-Cookie: device_id=550e8400...; HttpOnly; Secure; SameSite=Strict; Path=/
Set-Cookie: csrf_token=xyz123...; Secure; SameSite=Strict; Path=/
```

---

## 🛠️ Advanced Usage

### Manual Refresh
Force a token refresh manually (e.g., before a sensitive operation).

```javascript
try {
  await sessClient.refresh();
  console.log('Token refreshed successfully');
} catch (err) {
  console.error('Refresh failed (session expired?):', err);
  // Redirect to login
}
```

### Custom Fetch Implementation
Use a polyfill or a specific fetch wrapper (e.g., `node-fetch` in SSR contexts).

```javascript
import { sc } from 'sessvm-client';
import fetch from 'node-fetch';

const ssrClient = sc({
  ep: '/api/refresh',
  ft: fetch,
  se: false // Disable secure flag for local SSR testing
});
```

---

## 🧪 Development & Testing

```bash
# Install dependencies
npm install

# Run tests (if applicable in your dev environment)
npm test
```

---

## 📄 License

Dual-licensed under your choice of LGPL-3.0-only or GPL-3.0-only. See the
repository license files for details.
