export const TOKEN_TYPE_CODES = {
  access: "A",
  refresh: "R",
  session: "S",
  device: "D",
  temporary: "T",
} as const;

export type TokenTypeCode =
  (typeof TOKEN_TYPE_CODES)[keyof typeof TOKEN_TYPE_CODES];

export type TokenSchemaVersion = 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9;

export type TokenHeader = `${TokenTypeCode}${TokenSchemaVersion}`;

export const ACCESS_TOKEN_HEADER = "A1" as const;
export const REFRESH_TOKEN_HEADER = "R1" as const;

export type AccessTokenHeader = typeof ACCESS_TOKEN_HEADER;
export type RefreshTokenHeader = typeof REFRESH_TOKEN_HEADER;

export interface ParsedTokenHeader<
  TType extends TokenTypeCode = TokenTypeCode,
  TVersion extends TokenSchemaVersion = TokenSchemaVersion,
> {
  readonly type: TType;
  readonly version: TVersion;
  readonly value: `${TType}${TVersion}`;
}

export interface SerializedTokenParts<THeader extends TokenHeader = TokenHeader> {
  readonly header: THeader;
  readonly payload: string;
  readonly signature: string;
}

const TOKEN_TYPE_CODE_SET = new Set<TokenTypeCode>(
  Object.values(TOKEN_TYPE_CODES),
);

export function createTokenHeader<
  TType extends TokenTypeCode,
  TVersion extends TokenSchemaVersion,
>(type: TType, version: TVersion): `${TType}${TVersion}` {
  return `${type}${version}` as `${TType}${TVersion}`;
}

export function parseTokenHeader(value: string): ParsedTokenHeader | null {
  if (value.length !== 2) {
    return null;
  }

  const type = value[0];
  const version = Number(value[1]);

  if (!TOKEN_TYPE_CODE_SET.has(type as TokenTypeCode)) {
    return null;
  }

  if (!Number.isInteger(version) || version < 1 || version > 9) {
    return null;
  }

  return {
    type: type as TokenTypeCode,
    version: version as TokenSchemaVersion,
    value: value as TokenHeader,
  };
}

export function isTokenHeader(value: string): value is TokenHeader {
  return parseTokenHeader(value) !== null;
}

export function splitSerializedToken(
  token: string,
): SerializedTokenParts | null {
  const firstSeparatorIndex = token.indexOf(".");
  const lastSeparatorIndex = token.lastIndexOf(".");

  if (firstSeparatorIndex !== 2 || lastSeparatorIndex <= firstSeparatorIndex) {
    return null;
  }

  const header = token.slice(0, 2);

  if (!isTokenHeader(header)) {
    return null;
  }

  const payload = token.slice(firstSeparatorIndex + 1, lastSeparatorIndex);
  const signature = token.slice(lastSeparatorIndex + 1);

  if (payload.length === 0 || signature.length === 0) {
    return null;
  }

  return {
    header,
    payload,
    signature,
  };
}
