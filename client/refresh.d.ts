export type SameSite =
  | "Strict"
  | "Lax"
  | "None"
  | "strict"
  | "lax"
  | "none";

export type FetchTransport = (
  input: RequestInfo | URL,
  init?: RequestInit,
) => Promise<Response>;

export interface ClientOptions {
  readonly ac?: string;
  readonly cc?: string;
  readonly dc?: string;
  readonly aa?: number;
  readonly ca?: number;
  readonly da?: number;
  readonly ep?: RequestInfo | URL;
  readonly ft?: FetchTransport;
  readonly se?: boolean;
  readonly ss?: SameSite;
}

export interface AuthInput {
  readonly atk?: string | null;
  readonly csrf?: string;
  readonly did?: string;
  readonly headers?: HeadersInit;
}

export interface RefreshInput {
  readonly atk?: string | null;
  readonly did?: string;
  readonly ep?: RequestInfo | URL;
  readonly aa?: number;
}

export interface RefreshResult {
  readonly ok: boolean;
  readonly refreshed: boolean;
  readonly atk: string | null;
  readonly sid: string | null;
  readonly rsn?: string;
  readonly status?: number;
  readonly [key: string]: unknown;
}

export type AuthenticatedRequestInit = RequestInit & AuthInput;

export interface GraphqlInput extends AuthInput {}

export interface GraphqlContext {
  readonly headers: Headers;
  readonly fetchOptions: {
    readonly headers: Headers;
    readonly credentials: "include";
  };
}

export interface GqlInput extends Omit<AuthInput, "headers"> {
  readonly query: string;
  readonly variables?: Record<string, unknown>;
  readonly operationName?: string;
  readonly headers?: Record<string, string>;
}

export interface WebSocketInput {
  readonly atk?: string | null;
  readonly did?: string;
}

export interface WebSocketAuth {
  readonly did: string;
  readonly connectionParams: {
    readonly Authorization: string;
    readonly "X-Session-Device": string;
  };
  readonly protocols: readonly string[];
}

export interface SessionClient {
  getAccessToken(): string | null;
  setAccessToken(atk: string, maxAge?: number): void;
  getCsrfToken(): string;
  getDeviceId(): string;
  authHeaders(input?: AuthInput): Headers;
  refresh(input?: RefreshInput): Promise<RefreshResult>;
  http(input?: AuthInput): Headers;
  request(
    url: RequestInfo | URL,
    input?: AuthenticatedRequestInit,
  ): Promise<Response>;
  graphql(input?: GraphqlInput): GraphqlContext;
  gql(endpointUrl: RequestInfo | URL, input: GqlInput): Promise<Response>;
  ws(input?: WebSocketInput): WebSocketAuth;
}

export function sc(options?: ClientOptions): SessionClient;

export type RefreshOptions = ClientOptions & RefreshInput;

export function rf(options?: RefreshOptions): Promise<RefreshResult>;
