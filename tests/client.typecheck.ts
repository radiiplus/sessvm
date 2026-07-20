import {
  rf,
  sc,
  type RefreshResult,
  type SessionClient,
} from "../client/refresh.js";

const client: SessionClient = sc({
  ep: "/auth/refresh",
  se: false,
  ss: "Strict",
});

const headers: Headers = client.http({
  atk: "A1.payload.signature",
  did: "device-001",
  csrf: "csrf-001",
});

const request: Promise<Response> = client.request("/api/profile", {
  method: "GET",
});

const gql: Promise<Response> = client.gql("/graphql", {
  query: "query Me { me { id } }",
  variables: {
    limit: 1,
  },
});

const refresh: Promise<RefreshResult> = client.refresh();
const oneShot: Promise<RefreshResult> = rf({
  ep: "/auth/refresh",
  se: false,
});

void headers;
void request;
void gql;
void refresh;
void oneShot;
