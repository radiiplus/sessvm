import { createHash } from "node:crypto";
import {
  ACTIVE_STATE,
  ISSUED_STATE,
  ROTATED_STATE,
  fpp,
  fpx,
  createAccessPolicy,
  createAccessTokenPayload,
  createBindingFromFingerprint,
  createBindingHash,
  createRefreshPolicy,
  createRefreshValue,
  nodeBindMac,
  nodeMac,
  parseAccessToken,
  signAccessToken,
  splitSerializedToken,
  verifyBindingHash,
  type AccessPolicy,
  type BindIn,
  type DeviceFingerprint,
  type FingerprintPolicy,
  type FingerprintVerdict,
  type RiskMode,
  type FingerprintExtractor,
  type MacKey,
  type RequestLike,
  type RefreshPolicy,
  type Rng,
  type Ssn,
  type Store,
} from "./index";

export interface SessionCfg {
  readonly iss: string;
  readonly aud: string;
  readonly access?: AccessPolicy;
  readonly refresh?: RefreshPolicy;
  readonly accessKey: MacKey;
  readonly bindKey: Uint8Array;
  readonly rng?: Rng;
  readonly fp?: FingerprintExtractor;
  readonly fpp?: FingerprintPolicy;
  readonly risk?: RiskMode;
  readonly stable?: boolean;
}

export interface StartIn {
  readonly sub: string;
  readonly did: string;
  readonly scp: readonly string[];
  readonly now: number;
  readonly dn?: string;
  readonly loc?: string;
  readonly bind?: BindIn;
  readonly req?: RequestLike;
}

export interface StartOut {
  readonly ssn: Ssn;
  readonly atk: string;
  readonly rtk: string;
}

export interface RotateIn {
  readonly tk: string;
  readonly did: string;
  readonly now: number;
  readonly dn?: string;
  readonly loc?: string;
  readonly bind?: BindIn;
  readonly req?: RequestLike;
}

export interface RotateOut {
  readonly ok: true;
  readonly out: StartOut;
}

export interface RotateFail {
  readonly ok: false;
  readonly rsn:
    | "refresh-not-found"
    | "refresh-reuse-detected"
    | "refresh-not-active"
    | "device-mismatch"
    | "binding-mismatch";
  readonly sid?: string;
  readonly verdict?: FingerprintVerdict;
}

export interface RevokeIn {
  readonly sid: string;
  readonly rsn: string;
  readonly now: number;
}

export interface ExchangeIn {
  readonly atk: string;
  readonly did: string;
  readonly now: number;
  readonly req: RequestLike;
  readonly dn?: string;
  readonly loc?: string;
}

export interface ExchangeOut {
  readonly ok: boolean;
  readonly refreshed: boolean;
  readonly atk: string | null;
  readonly sid: string | null;
  readonly rsn?:
    | "invalid-access-format"
    | "invalid-access-token"
    | "session-not-found"
    | "session-not-active"
    | "device-mismatch"
    | "binding-mismatch"
    | "exchange-failed";
  readonly verdict?: FingerprintVerdict;
}

function createId(prefix: string, value: string): string {
  return `${prefix}-${value}`;
}

function deriveId(parts: readonly string[]): string {
  return createHash("sha256")
    .update(parts.join(":"))
    .digest("hex")
    .slice(0, 24);
}

function createNextAccessJti(
  sid: string,
  priorJti: string,
  now: number,
): string {
  return createId("jti", deriveId([sid, priorJti, String(now)]));
}

function isExpired(expiresAt: number, now: number): boolean {
  return expiresAt <= now;
}

function assertDeviceId(did: string): void {
  if (did.trim().length === 0) {
    throw new Error("Session device UUID is required.");
  }
}

function deviceName(
  fingerprint: DeviceFingerprint | undefined,
  explicit: string | undefined,
): string | undefined {
  if (explicit !== undefined) {
    return explicit;
  }

  if (fingerprint?.br === undefined || fingerprint.br === null) {
    return undefined;
  }

  return fingerprint.bv === undefined || fingerprint.bv === null
    ? fingerprint.br
    : `${fingerprint.br} ${fingerprint.bv}`;
}

export class Ssv {
  readonly store: Store;

  private readonly cfg: SessionCfg;

  private policy(): FingerprintPolicy {
    return (
      this.cfg.fpp ??
      fpp({
        ...(this.cfg.risk !== undefined
          ? { mode: this.cfg.risk }
          : {}),
        ...(this.cfg.stable !== undefined
          ? { stable: this.cfg.stable }
          : {}),
      })
    );
  }

  constructor(store: Store, cfg: SessionCfg) {
    this.store = store;
    this.cfg = cfg;
  }

  private async resolveBinding(
    input: Pick<StartIn, "bind" | "req"> | Pick<RotateIn, "bind" | "req">,
  ): Promise<{
    bind: BindIn;
    fp?: DeviceFingerprint;
  }> {
    if (input.bind !== undefined) {
      return {
        bind: input.bind,
      };
    }

    if (input.req === undefined) {
      throw new Error("Session binding requires either bind input or a request.");
    }

    const extractor = this.cfg.fp ?? fpx();
    const fingerprint = await extractor.extract(input.req);
    return {
      bind: createBindingFromFingerprint(fingerprint),
      fp: fingerprint,
    };
  }

  async start(input: StartIn): Promise<StartOut> {
    assertDeviceId(input.did);
    const resolved = await this.resolveBinding(input);
    const accessPolicy = this.cfg.access ?? createAccessPolicy();
    const refreshPolicy =
      this.cfg.refresh ?? createRefreshPolicy("r1");
    const refreshValue = createRefreshValue(refreshPolicy, this.cfg.rng);
    const dn = deviceName(resolved.fp, input.dn);
    const bindingHash = await createBindingHash(
      resolved.bind,
      this.cfg.bindKey,
      nodeBindMac,
    );

    const sid = createId(
      "sid",
      deriveId([input.sub, String(input.now), refreshValue.val]),
    );
    const jti = createId(
      "jti",
      deriveId([sid, refreshValue.val, String(input.now)]),
    );
    const fid = createId(
      "fid",
      deriveId([input.sub, sid]),
    );
    const ssn: Ssn = {
      id: sid,
      sub: input.sub,
      did: input.did,
      iss: this.cfg.iss,
      aud: this.cfg.aud,
      scp: [...input.scp],
      st: ACTIVE_STATE,
      iat: input.now,
      exp: input.now + refreshPolicy.ttl,
      rat: input.now,
      la: input.now,
      ajt: jti,
      bh: bindingHash,
      ...(dn !== undefined ? { dn } : {}),
      ...(input.loc !== undefined ? { loc: input.loc } : {}),
      ...(resolved.fp !== undefined ? { fp: resolved.fp } : {}),
    };

    await this.store.createSession({
      ssn,
      rtk: {
        id: jti,
        tk: refreshValue.val,
        fid,
        kid: refreshValue.kid,
        hd: refreshValue.hd,
        su: input.sub,
        sid,
        jt: jti,
        bh: bindingHash,
        st: ISSUED_STATE,
        iat: input.now,
        exp: input.now + refreshPolicy.ttl,
        ...(resolved.fp !== undefined ? { fp: resolved.fp } : {}),
      },
    });

    const atk = await signAccessToken(
      createAccessTokenPayload({
        su: input.sub,
        jt: jti,
        ia: input.now,
        sc: input.scp,
        ttl: accessPolicy.ttl,
      }),
      this.cfg.accessKey,
      nodeMac,
    );

    return {
      ssn,
      atk: atk.tk,
      rtk: refreshValue.val,
    };
  }

  async rotate(input: RotateIn): Promise<RotateOut | RotateFail> {
    assertDeviceId(input.did);
    const hit = await this.store.getSessionByRefreshToken({
      tk: input.tk,
    });

    if (hit === null) {
      return {
        ok: false,
        rsn: "refresh-not-found",
      };
    }

    if (isExpired(hit.rtk.exp, input.now) || isExpired(hit.ssn.exp, input.now)) {
      await this.store.revokeSession({
        sid: hit.ssn.id,
        rsn: "refresh-token-expired",
        at: input.now,
      });
      return {
        ok: false,
        rsn: "refresh-not-active",
        sid: hit.ssn.id,
      };
    }

    if (hit.rtk.st === ROTATED_STATE) {
      await this.store.revokeRefreshFamily({
        sid: hit.ssn.id,
        tk: input.tk,
        at: input.now,
      });
      return {
        ok: false,
        rsn: "refresh-reuse-detected",
        sid: hit.ssn.id,
      };
    }

    if (hit.rtk.st !== ACTIVE_STATE && hit.rtk.st !== ISSUED_STATE) {
      return {
        ok: false,
        rsn: "refresh-not-active",
        sid: hit.ssn.id,
      };
    }

    if (hit.ssn.did !== input.did) {
      return {
        ok: false,
        rsn: "device-mismatch",
        sid: hit.ssn.id,
      };
    }

    const resolved = await this.resolveBinding(input);
    const risk = this.cfg.risk ?? "RELAXED";
    const verdict =
      risk !== "STRICT" &&
      resolved.fp !== undefined &&
      hit.rtk.fp !== undefined
        ? this.policy().compare(hit.rtk.fp, resolved.fp)
        : undefined;
    const ok =
      verdict !== undefined
        ? verdict.ok
        : await verifyBindingHash(
            hit.rtk.bh,
            resolved.bind,
            this.cfg.bindKey,
            nodeBindMac,
          );

    if (!ok) {
      return {
        ok: false,
        rsn: "binding-mismatch",
        sid: hit.ssn.id,
        ...(verdict !== undefined ? { verdict } : {}),
      };
    }

    const accessPolicy = this.cfg.access ?? createAccessPolicy();
    const refreshPolicy =
      this.cfg.refresh ?? createRefreshPolicy(hit.rtk.kid);
    const refreshValue = createRefreshValue(refreshPolicy, this.cfg.rng);
    const nextJti = createId(
      "jti",
      deriveId([hit.ssn.id, refreshValue.val, String(input.now)]),
    );
    const nextBindingHash = await createBindingHash(
      resolved.bind,
      this.cfg.bindKey,
      nodeBindMac,
    );

    const rotation = await this.store.rotateRefreshToken({
      cur: {
        ...hit.rtk,
        st: ACTIVE_STATE,
      },
      nxt: {
        id: nextJti,
        tk: refreshValue.val,
        fid: hit.rtk.fid,
        kid: refreshValue.kid,
        hd: refreshValue.hd,
        su: hit.ssn.sub,
        sid: hit.ssn.id,
        jt: nextJti,
        bh: nextBindingHash,
        st: ISSUED_STATE,
        iat: input.now,
        exp: input.now + refreshPolicy.ttl,
        ...(resolved.fp !== undefined ? { fp: resolved.fp } : hit.rtk.fp !== undefined ? { fp: hit.rtk.fp } : {}),
      },
      at: input.now,
    });

    const atk = await signAccessToken(
      createAccessTokenPayload({
        su: hit.ssn.sub,
        jt: nextJti,
        ia: input.now,
        sc: hit.ssn.scp,
        ttl: accessPolicy.ttl,
      }),
      this.cfg.accessKey,
      nodeMac,
    );

    return {
      ok: true,
      out: {
        ssn: rotation.ssn,
        atk: atk.tk,
        rtk: refreshValue.val,
      },
    };
  }

  async revoke(input: RevokeIn): Promise<boolean> {
    const plan = await this.store.revokeSession({
      sid: input.sid,
      rsn: input.rsn,
      at: input.now,
    });

    return plan !== null;
  }

  async exchange(input: ExchangeIn): Promise<ExchangeOut> {
    assertDeviceId(input.did);
    const parts = splitSerializedToken(input.atk);

    if (parts === null || parts.header[0] !== "A") {
      return {
        ok: false,
        refreshed: false,
        atk: null,
        sid: null,
        rsn: "invalid-access-format",
      };
    }

    const accessPolicy = this.cfg.access ?? createAccessPolicy();
    const payload = await parseAccessToken(
      input.atk,
      this.cfg.accessKey,
      nodeMac,
      accessPolicy,
    );

    if (payload === null) {
      return {
        ok: false,
        refreshed: false,
        atk: null,
        sid: null,
        rsn: "invalid-access-token",
      };
    }

    const hit = await this.store.getSessionByAccessToken({
      jt: payload.jt,
    });

    if (hit === null) {
      return {
        ok: false,
        refreshed: false,
        atk: null,
        sid: null,
        rsn: "session-not-found",
      };
    }

    if (hit.ssn.st !== ACTIVE_STATE) {
      return {
        ok: false,
        refreshed: false,
        atk: null,
        sid: hit.ssn.id,
        rsn: "session-not-active",
      };
    }

    if (hit.ssn.did !== input.did) {
      return {
        ok: false,
        refreshed: false,
        atk: null,
        sid: hit.ssn.id,
        rsn: "device-mismatch",
      };
    }

    const resolved = await this.resolveBinding({
      req: input.req,
    });
    const risk = this.cfg.risk ?? "RELAXED";
    const verdict =
      risk !== "STRICT" &&
      resolved.fp !== undefined &&
      hit.ssn.fp !== undefined
        ? this.policy().compare(hit.ssn.fp, resolved.fp)
        : undefined;
    const bound =
      verdict !== undefined
        ? verdict.ok
        : hit.ssn.bh !== undefined &&
          await verifyBindingHash(
            hit.ssn.bh,
            resolved.bind,
            this.cfg.bindKey,
            nodeBindMac,
          );

    if (!bound) {
      return {
        ok: false,
        refreshed: false,
        atk: null,
        sid: hit.ssn.id,
        rsn: "binding-mismatch",
        ...(verdict !== undefined ? { verdict } : {}),
      };
    }

    const nextBindingHash = await createBindingHash(
      resolved.bind,
      this.cfg.bindKey,
      nodeBindMac,
    );
    const nextDeviceName = deviceName(resolved.fp, input.dn);

    if (!isExpired(payload.ex, input.now)) {
      await this.store.exchangeAccessToken({
        sid: hit.ssn.id,
        ajt: payload.jt,
        at: input.now,
        bh: nextBindingHash,
        ...(resolved.fp !== undefined ? { fp: resolved.fp } : {}),
        ...(nextDeviceName !== undefined ? { dn: nextDeviceName } : {}),
        ...(input.loc !== undefined ? { loc: input.loc } : {}),
      });

      return {
        ok: true,
        refreshed: false,
        atk: input.atk,
        sid: hit.ssn.id,
      };
    }

    const nextJti = createNextAccessJti(hit.ssn.id, payload.jt, input.now);
    const exchanged = await this.store.exchangeAccessToken({
      sid: hit.ssn.id,
      ajt: nextJti,
      at: input.now,
      bh: nextBindingHash,
      ...(resolved.fp !== undefined ? { fp: resolved.fp } : {}),
      ...(nextDeviceName !== undefined ? { dn: nextDeviceName } : {}),
      ...(input.loc !== undefined ? { loc: input.loc } : {}),
    });

    if (exchanged === null) {
      return {
        ok: false,
        refreshed: false,
        atk: null,
        sid: hit.ssn.id,
        rsn: "exchange-failed",
      };
    }

    const signed = await signAccessToken(
      createAccessTokenPayload({
        su: hit.ssn.sub,
        jt: nextJti,
        ia: input.now,
        sc: hit.ssn.scp,
        ttl: accessPolicy.ttl,
      }),
      this.cfg.accessKey,
      nodeMac,
    );

    return {
      ok: true,
      refreshed: true,
      atk: signed.tk,
      sid: hit.ssn.id,
    };
  }
}

export function ssv(
  store: Store,
  cfg: SessionCfg,
): Ssv {
  return new Ssv(store, cfg);
}
