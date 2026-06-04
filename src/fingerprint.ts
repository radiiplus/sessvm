import { createHash } from "node:crypto";

export interface RequestLike {
  readonly headers: {
    get(name: string): string | null;
  };
  readonly ip?: string | null;
  readonly tls?: {
    readonly ja3?: string | null;
  } | null;
}

export interface DeviceFingerprint {
  readonly ua: string;
  readonly al: string;
  readonly ja: string | null;
  readonly ip: string | null;
  readonly br?: string | null;
  readonly bv?: string | null;
  readonly asn?: string | null;
}

export interface FingerprintExtractor {
  extract(request: RequestLike): Promise<DeviceFingerprint>;
}

export type FingerprintField = "ua" | "al" | "ja" | "ip";
export type RiskMode = "STRICT" | "RELAXED" | "ADAPTIVE";

export type FingerprintLangMode =
  | "exact"
  | "primary"
  | "allow-missing"
  | "ignore";

export type FingerprintSignalMode =
  | "exact"
  | "allow-missing"
  | "ignore";

export interface FingerprintPolicyOptions {
  readonly min?: number;
  readonly al?: FingerprintLangMode;
  readonly ja?: FingerprintSignalMode;
  readonly ip?: FingerprintSignalMode;
  readonly mode?: RiskMode;
  readonly asn?: FingerprintSignalMode;
  readonly browser?: "exact" | "family" | "ignore";
  readonly stable?: boolean;
}

export interface FingerprintVerdict {
  readonly ok: boolean;
  readonly matched: readonly FingerprintField[];
  readonly failed: readonly FingerprintField[];
  readonly skipped: readonly FingerprintField[];
  readonly score: number;
  readonly need: number;
  readonly mode: RiskMode;
}

export interface FingerprintPolicy {
  compare(
    expected: DeviceFingerprint,
    actual: DeviceFingerprint,
  ): FingerprintVerdict;
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function normalizeHeader(value: string | null): string {
  if (value === null) {
    return "";
  }

  return value.trim().replace(/\s+/g, " ").toLowerCase();
}

function normalizeLanguage(value: string | null): string {
  return normalizeHeader(value);
}

function normalizeBrowser(
  value: string | null,
): { br: string | null; bv: string | null } {
  const source = normalizeHeader(value);

  if (source.length === 0) {
    return {
      br: null,
      bv: null,
    };
  }

  const patterns = [
    { name: "edge", rx: /\bedg\/(\d+)/ },
    { name: "chrome", rx: /\bchrome\/(\d+)/ },
    { name: "firefox", rx: /\bfirefox\/(\d+)/ },
    { name: "safari", rx: /\bversion\/(\d+).+safari\// },
  ] as const;

  for (const pattern of patterns) {
    const match = source.match(pattern.rx);

    if (match?.[1] !== undefined) {
      return {
        br: pattern.name,
        bv: match[1],
      };
    }
  }

  return {
    br: "other",
    bv: null,
  };
}

function asValue(value: string | null): string | null {
  if (value === null) {
    return null;
  }

  return value.length === 0 ? null : value;
}

function hashUa(value: string | null): string {
  const normalized = normalizeHeader(value);
  return normalized.length === 0 ? "" : sha256(normalized);
}

function normalizeJa3(value: string | null | undefined): string | null {
  if (value === null || value === undefined) {
    return null;
  }

  const normalized = normalizeHeader(value);
  return normalized.length === 0 ? null : normalized;
}

function primaryLanguage(value: string): string | null {
  if (value.length === 0) {
    return null;
  }

  const first = value.split(",")[0]?.trim();

  if (first === undefined || first.length === 0) {
    return null;
  }

  const primary = first.split("-")[0]?.trim();
  return primary === undefined || primary.length === 0 ? null : primary;
}

type CompareResult = "hit" | "miss" | "skip";

function compareSignal(
  expected: string | null,
  actual: string | null,
  mode: FingerprintSignalMode,
): CompareResult {
  if (mode === "ignore") {
    return "skip";
  }

  const left = asValue(expected);
  const right = asValue(actual);

  if (mode === "allow-missing" && (left === null || right === null)) {
    return "skip";
  }

  if (left === null && right === null) {
    return "skip";
  }

  if (left === null || right === null) {
    return "miss";
  }

  return left === right ? "hit" : "miss";
}

function compareBrowser(
  expected: DeviceFingerprint,
  actual: DeviceFingerprint,
  mode: "exact" | "family" | "ignore",
): CompareResult {
  if (mode === "ignore") {
    return "skip";
  }

  const leftFamily = asValue(expected.br ?? null);
  const rightFamily = asValue(actual.br ?? null);

  if (leftFamily === null && rightFamily === null) {
    return "skip";
  }

  if (leftFamily === null || rightFamily === null) {
    return "miss";
  }

  if (leftFamily !== rightFamily) {
    return "miss";
  }

  if (mode === "family") {
    return "hit";
  }

  const leftVersion = asValue(expected.bv ?? null);
  const rightVersion = asValue(actual.bv ?? null);

  if (leftVersion === null && rightVersion === null) {
    return "hit";
  }

  if (leftVersion === null || rightVersion === null) {
    return "miss";
  }

  return leftVersion === rightVersion ? "hit" : "miss";
}

function compareLanguage(
  expected: string,
  actual: string,
  mode: FingerprintLangMode,
): CompareResult {
  if (mode === "ignore") {
    return "skip";
  }

  const left = asValue(expected);
  const right = asValue(actual);

  if (
    (mode === "allow-missing" || mode === "primary") &&
    (left === null || right === null)
  ) {
    return "skip";
  }

  if (left === null && right === null) {
    return "skip";
  }

  if (left === null || right === null) {
    return "miss";
  }

  if (left === right) {
    return "hit";
  }

  if (mode !== "primary") {
    return "miss";
  }

  const leftPrimary = primaryLanguage(left);
  const rightPrimary = primaryLanguage(right);

  if (leftPrimary === null || rightPrimary === null) {
    return "miss";
  }

  return leftPrimary === rightPrimary ? "hit" : "miss";
}

function pushResult(
  result: CompareResult,
  field: FingerprintField,
  matched: FingerprintField[],
  failed: FingerprintField[],
  skipped: FingerprintField[],
): number {
  if (result === "hit") {
    matched.push(field);
    return 1;
  }

  if (result === "miss") {
    failed.push(field);
    return 0;
  }

  skipped.push(field);
  return 0;
}

function normalizeIpv4(ip: string): string | null {
  const parts = ip.split(".");

  if (parts.length !== 4) {
    return null;
  }

  const nums = parts.map((part) => Number(part));

  if (nums.some((num) => !Number.isInteger(num) || num < 0 || num > 255)) {
    return null;
  }

  return `${nums[0]}.${nums[1]}.${nums[2]}.0/24`;
}

function expandIpv6(input: string): string[] | null {
  const source = input.toLowerCase();

  if (!/^[0-9a-f:]+$/.test(source)) {
    return null;
  }

  if (source.includes("::")) {
    const parts = source.split("::");

    if (parts.length !== 2) {
      return null;
    }

    const leftPart = parts[0] ?? "";
    const rightPart = parts[1] ?? "";
    const left = leftPart.length === 0 ? [] : leftPart.split(":");
    const right = rightPart.length === 0 ? [] : rightPart.split(":");
    const fill = 8 - (left.length + right.length);

    if (fill < 0) {
      return null;
    }

    return [
      ...left,
      ...Array.from({ length: fill }, () => "0"),
      ...right,
    ].map((part) => part.padStart(4, "0"));
  }

  const parts = source.split(":");

  if (parts.length !== 8) {
    return null;
  }

  return parts.map((part) => part.padStart(4, "0"));
}

function normalizeIpv6(ip: string): string | null {
  const split = ip.split("%");
  const source = split[0];

  if (source === undefined) {
    return null;
  }

  const parts = expandIpv6(source);

  if (parts === null) {
    return null;
  }

  return `${parts.slice(0, 4).join(":")}::/64`;
}

export function maskIpPrefix(ip: string | null | undefined): string | null {
  if (ip === null || ip === undefined) {
    return null;
  }

  const trimmed = ip.trim();

  if (trimmed.length === 0) {
    return null;
  }

  if (trimmed.includes(".")) {
    return normalizeIpv4(trimmed);
  }

  if (trimmed.includes(":")) {
    return normalizeIpv6(trimmed);
  }

  return null;
}

export function dvc(
  request: RequestLike,
): DeviceFingerprint {
  const ua = request.headers.get("user-agent");
  const browser = normalizeBrowser(ua);

  return {
    ua: hashUa(ua),
    al: normalizeLanguage(request.headers.get("accept-language")),
    ja: normalizeJa3(request.tls?.ja3 ?? null),
    ip: maskIpPrefix(request.ip),
    ...(browser.br !== null ? { br: browser.br } : {}),
    ...(browser.bv !== null ? { bv: browser.bv } : {}),
    asn: null,
  };
}

export function fpp(
  options: FingerprintPolicyOptions = {},
): FingerprintPolicy {
  const mode = options.mode ?? "RELAXED";
  const stable = options.stable ?? false;
  const min =
    options.min ?? (mode === "STRICT" ? 4 : mode === "ADAPTIVE" && stable ? 3 : 2);
  const al =
    options.al ?? (mode === "STRICT" ? "exact" : "primary");
  const ja =
    options.ja ?? (mode === "STRICT" ? "exact" : "allow-missing");
  const ip =
    options.ip ?? (mode === "STRICT" ? "exact" : "ignore");
  const asn =
    options.asn ?? (mode === "STRICT" ? "exact" : "allow-missing");
  const browser =
    options.browser ?? (mode === "STRICT" ? "exact" : "family");

  if (!Number.isInteger(min) || min < 0 || min > 5) {
    throw new RangeError("Fingerprint policy min must be an integer between 0 and 5.");
  }

  return {
    compare(
      expected: DeviceFingerprint,
      actual: DeviceFingerprint,
    ): FingerprintVerdict {
      const matched: FingerprintField[] = [];
      const failed: FingerprintField[] = [];
      const skipped: FingerprintField[] = [];
      let score = 0;

      score += pushResult(
        compareBrowser(expected, actual, browser),
        "ua",
        matched,
        failed,
        skipped,
      );

      score += pushResult(
        compareLanguage(expected.al, actual.al, al),
        "al",
        matched,
        failed,
        skipped,
      );
      score += pushResult(
        compareSignal(expected.ja, actual.ja, ja),
        "ja",
        matched,
        failed,
        skipped,
      );
      score += pushResult(
        compareSignal(expected.ip, actual.ip, ip),
        "ip",
        matched,
        failed,
        skipped,
      );
      score += pushResult(
        compareSignal(expected.asn ?? null, actual.asn ?? null, asn),
        "ip",
        matched,
        failed,
        skipped,
      );
      const available = score + failed.length;
      const need = Math.min(min, available);

      return {
        ok: score >= need,
        matched,
        failed,
        skipped,
        score,
        need,
        mode,
      };
    },
  };
}

export function stp(): FingerprintPolicy {
  return fpp({
    mode: "STRICT",
  });
}

export function rlp(): FingerprintPolicy {
  return fpp({
    mode: "RELAXED",
  });
}

export function adp(stable = false): FingerprintPolicy {
  return fpp({
    mode: "ADAPTIVE",
    stable,
  });
}

export function asn(
  fingerprint: DeviceFingerprint,
  asn: string | null,
): DeviceFingerprint {
  return {
    ...fingerprint,
    asn: asn === null ? null : normalizeHeader(asn),
  };
}

export function fpx(): FingerprintExtractor {
  return {
    async extract(request: RequestLike): Promise<DeviceFingerprint> {
      return dvc(request);
    },
  };
}
