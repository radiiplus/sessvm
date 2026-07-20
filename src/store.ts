import {
  ACTIVE_STATE,
  ISSUED_STATE,
  REVOKED_STATE,
  REUSE_DETECTED_STATE,
  ROTATED_STATE,
  type ActiveState,
  type IssuedState,
  type RefreshTokenRecord,
  type RotatedState,
  type RevokedState,
  type TokenLifecycleState,
} from "./tokens";
import type { DeviceFingerprint } from "./fingerprint";

export interface Ssn {
  readonly id: string;
  readonly sub: string;
  readonly did: string;
  readonly iss: string;
  readonly aud: string;
  readonly scp: readonly string[];
  readonly st: TokenLifecycleState;
  readonly iat: number;
  readonly exp: number;
  readonly rat: number;
  readonly ajt?: string;
  readonly bh?: string;
  readonly fp?: DeviceFingerprint;
  readonly dn?: string;
  readonly loc?: string;
  readonly la?: number;
  readonly uat?: number;
  readonly ext?: Record<string, string | number | boolean | null>;
}

export interface Rtk<
  TState extends TokenLifecycleState = TokenLifecycleState,
> {
  readonly id: string;
  readonly tk: string;
  readonly fid: string;
  readonly kid: string;
  readonly hd: string;
  readonly su: string;
  readonly sid: string;
  readonly jt: string;
  readonly bh: string;
  readonly st: TState;
  readonly iat: number;
  readonly exp: number;
  readonly fp?: DeviceFingerprint;
  readonly rid?: string;
  readonly rsn?: string;
}

export interface Key {
  readonly pk: string;
  readonly sk: string;
}

export type RefCardinality = "one" | "many";

export interface Ref {
  readonly key: Key;
  readonly val: string;
  readonly cardinality: RefCardinality;
}

export interface ListRef {
  readonly key: Key;
  readonly vals: readonly string[];
}

export interface SetRec {
  readonly key: Key;
  readonly val: Ssn | Rtk;
  readonly exp?: number;
}

export interface DelRec {
  readonly key: Key;
}

export interface Put {
  readonly ssn: Ssn;
  readonly rtk: Rtk<IssuedState | ActiveState>;
  readonly set: readonly SetRec[];
  readonly ref: readonly Ref[];
}

export interface Hit {
  readonly ssn: Ssn;
  readonly rtk: Rtk;
}

export interface Rev {
  readonly ssn: Ssn;
  readonly rtk: Rtk<RevokedState>;
  readonly set: readonly SetRec[];
  readonly drop: readonly string[];
}

export interface Fam {
  readonly ssn: Ssn;
  readonly fam: readonly Rtk[];
  readonly set: readonly SetRec[];
  readonly drop: readonly string[];
}

export interface Reu {
  readonly ssn: Ssn;
  readonly rtk: Rtk;
  readonly fam: readonly Rtk[];
  readonly set: readonly SetRec[];
  readonly drop: readonly string[];
}

export interface Acc {
  readonly ssn: Ssn;
  readonly set: readonly SetRec[];
  readonly drop: readonly string[];
  readonly ref: readonly Ref[];
}

export interface Rot {
  readonly ssn: Ssn;
  readonly prv: Rtk;
  readonly nxt: Rtk<IssuedState>;
  readonly set: readonly SetRec[];
  readonly del: readonly DelRec[];
  readonly drop: readonly string[];
  readonly ref: readonly Ref[];
}

export interface CrtIn {
  readonly ssn: Ssn;
  readonly rtk: Rtk<IssuedState | ActiveState>;
}

export interface GetIn {
  readonly tk: string;
}

export interface GetByAccessIn {
  readonly jt: string;
}

export interface AccessHit {
  readonly ssn: Ssn;
}

export interface DevIn {
  readonly sub: string;
  readonly did: string;
}

export interface LstIn {
  readonly sub: string;
}

export interface Lst {
  readonly id: string;
  readonly sub: string;
  readonly did: string;
  readonly st: ActiveState;
  readonly ca: number;
  readonly la: number;
  readonly dn?: string;
  readonly loc?: string;
}

export interface RevIn {
  readonly sid: string;
  readonly rsn: string;
  readonly at: number;
}

export interface ReuIn {
  readonly sid: string;
  readonly tk: string;
  readonly at: number;
}

export interface FamIn {
  readonly sid: string;
  readonly at: number;
  readonly rsn: string;
}

export interface AccIn {
  readonly sid: string;
  readonly ajt: string;
  readonly at: number;
  readonly bh?: string;
  readonly fp?: DeviceFingerprint;
  readonly dn?: string;
  readonly loc?: string;
}

export interface RotIn {
  readonly cur: Rtk<ActiveState>;
  readonly nxt: Rtk<IssuedState>;
  readonly at: number;
}

export interface Kv {
  put(rows: readonly SetRec[]): Promise<void>;
  get(key: Key): Promise<Ssn | Rtk | null>;
  del(rows: readonly DelRec[]): Promise<void>;
  bind(refs: readonly Ref[]): Promise<void>;
  read(val: string): Promise<Key | null>;
  list(val: string): Promise<readonly Key[]>;
  drop(vals: readonly string[]): Promise<void>;
}

export interface Store {
  readonly kv: Kv;
  createSession(input: CrtIn): Promise<Put>;
  getSessionByRefreshToken(input: GetIn): Promise<Hit | null>;
  getSessionByAccessToken(input: GetByAccessIn): Promise<AccessHit | null>;
  getSessionByDevice(input: DevIn): Promise<AccessHit | null>;
  listActiveSessions(input: LstIn): Promise<readonly Lst[]>;
  revokeSession(input: RevIn): Promise<Rev | null>;
  revokeSessionFamily(input: FamIn): Promise<Fam | null>;
  revokeRefreshFamily(input: ReuIn): Promise<Reu | null>;
  exchangeAccessToken(input: AccIn): Promise<Acc | null>;
  rotateRefreshToken(input: RotIn): Promise<Rot>;
}

export function ssnKey(id: string): Key {
  return {
    pk: "SSN",
    sk: id,
  };
}

export function rtkKey(id: string): Key {
  return {
    pk: "RTK",
    sk: id,
  };
}

export function rtkRef(id: string): string {
  return `RTV:${id}`;
}

export function sidRef(id: string): string {
  return `SID:${id}`;
}

export function fidRef(id: string): string {
  return `FID:${id}`;
}

export function ajtRef(id: string): string {
  return `AJT:${id}`;
}

export function usrRef(id: string): string {
  return `USR:${id}`;
}

export function devRef(sub: string, did: string): string {
  return `DEV:${sub}:${did}`;
}

export function mapRtk(token: RefreshTokenRecord): Rtk {
  const rtk: Rtk = {
    id: token.tokenId,
    tk: token.tokenId,
    fid: token.familyId,
    kid: "r1",
    hd: token.tokenHeader,
    su: "",
    sid: token.sessionId,
    jt: token.tokenId,
    bh: "",
    st: token.state,
    iat: token.issuedAt,
    exp: token.expiresAt,
  };

  if (token.replacedByTokenId !== undefined) {
    return {
      ...rtk,
      rid: token.replacedByTokenId,
      ...(token.revokedReason !== undefined
        ? { rsn: token.revokedReason }
        : {}),
    };
  }

  if (token.revokedReason !== undefined) {
    return {
      ...rtk,
      rsn: token.revokedReason,
    };
  }

  return rtk;
}

export function createSetRec(
  ssn: Ssn,
  rtk: Rtk,
): readonly SetRec[] {
  return [
    {
      key: ssnKey(ssn.id),
      val: ssn,
      exp: ssn.exp,
    },
    {
      key: rtkKey(rtk.id),
      val: rtk,
      exp: rtk.exp,
    },
  ];
}

export function createRef(rtk: Rtk): readonly Ref[] {
  return [
    {
      key: rtkKey(rtk.id),
      val: rtkRef(rtk.tk),
      cardinality: "one",
    },
    {
      key: rtkKey(rtk.id),
      val: sidRef(rtk.sid),
      cardinality: "one",
    },
    {
      key: rtkKey(rtk.id),
      val: fidRef(rtk.fid),
      cardinality: "many",
    },
  ];
}

export function createSessionRef(ssn: Ssn): readonly Ref[] {
  const refs: Ref[] = [
    {
      key: ssnKey(ssn.id),
      val: usrRef(ssn.sub),
      cardinality: "many",
    },
    {
      key: ssnKey(ssn.id),
      val: devRef(ssn.sub, ssn.did),
      cardinality: "one",
    },
  ];

  if (ssn.ajt === undefined) {
    return refs;
  }

  return [
    ...refs,
    {
      key: ssnKey(ssn.id),
      val: ajtRef(ssn.ajt),
      cardinality: "one",
    },
  ];
}

function sessionLookupRefs(ssn: Ssn): readonly string[] {
  return [
    sidRef(ssn.id),
    devRef(ssn.sub, ssn.did),
    ...(ssn.ajt === undefined ? [] : [ajtRef(ssn.ajt)]),
  ];
}

function familyLookupRefs(fam: readonly Rtk[]): readonly string[] {
  const first = fam[0];

  if (first === undefined) {
    return [];
  }

  return [
    fidRef(first.fid),
    ...fam.map((item) => rtkRef(item.tk)),
  ];
}

export function isSsn(value: Ssn | Rtk): value is Ssn {
  return "sub" in value;
}

export function isRtk(value: Ssn | Rtk): value is Rtk {
  return "tk" in value;
}

export function lst(ssn: Ssn): Lst | null {
  if (ssn.st !== ACTIVE_STATE) {
    return null;
  }

  return {
    id: ssn.id,
    sub: ssn.sub,
    did: ssn.did,
    st: ACTIVE_STATE,
    ca: ssn.iat,
    la: ssn.la ?? ssn.rat,
    ...(ssn.dn !== undefined ? { dn: ssn.dn } : {}),
    ...(ssn.loc !== undefined ? { loc: ssn.loc } : {}),
  };
}

export function lss(rows: readonly Ssn[]): readonly Lst[] {
  const byDevice = new Map<string, Lst>();

  for (const row of rows) {
    const view = lst(row);

    if (view === null) {
      continue;
    }

    const prior = byDevice.get(view.did);

    if (prior === undefined || prior.la <= view.la) {
      byDevice.set(view.did, view);
    }
  }

  return [...byDevice.values()].sort((left, right) => right.la - left.la);
}

export function createSessionPlan(input: CrtIn): Put {
  return {
    ssn: input.ssn,
    rtk: input.rtk,
    set: createSetRec(input.ssn, input.rtk),
    ref: [...createRef(input.rtk), ...createSessionRef(input.ssn)],
  };
}

export function createRevokePlan(
  ssn: Ssn,
  rtk: Rtk,
  at: number,
  rsn: string,
  fam: readonly Rtk[] = [rtk],
): Rev {
  const nextSsn: Ssn = {
    ...ssn,
    st: REVOKED_STATE,
    uat: at,
  };

  const nextRtk: Rtk<RevokedState> = {
    ...rtk,
    st: REVOKED_STATE,
    rsn,
  };

  return {
    ssn: nextSsn,
    rtk: nextRtk,
    set: createSetRec(nextSsn, nextRtk),
    drop: [...sessionLookupRefs(nextSsn), ...familyLookupRefs(fam)],
  };
}

export function createFamilyRevokePlan(
  ssn: Ssn,
  fam: readonly Rtk[],
  at: number,
  rsn: string,
): Fam {
  const nextSsn: Ssn = {
    ...ssn,
    st: REVOKED_STATE,
    uat: at,
  };

  return {
    ssn: nextSsn,
    fam,
    set: [
      {
        key: ssnKey(nextSsn.id),
        val: nextSsn,
        exp: nextSsn.exp,
      },
      ...fam.map((item) => ({
        key: rtkKey(item.id),
        val: {
          ...item,
          st: REVOKED_STATE,
          rsn,
        },
        exp: item.exp,
      })),
    ],
    drop: [...sessionLookupRefs(nextSsn), ...familyLookupRefs(fam)],
  };
}

export function createReusePlan(
  ssn: Ssn,
  rtk: Rtk<RotatedState> | Rtk,
  at: number,
  fam: readonly Rtk[],
): Reu {
  const nextSsn: Ssn = {
    ...ssn,
    st: REVOKED_STATE,
    uat: at,
  };

  const nextRtk: Rtk = {
    ...rtk,
    st: REUSE_DETECTED_STATE,
    rsn: "refresh-token-reuse-detected",
  };

  return {
    ssn: nextSsn,
    rtk: nextRtk,
    fam,
    set: [
      {
        key: ssnKey(nextSsn.id),
        val: nextSsn,
        exp: nextSsn.exp,
      },
      ...fam.map((item) => ({
        key: rtkKey(item.id),
        val:
          item.id === nextRtk.id
            ? nextRtk
            : {
                ...item,
                st: REVOKED_STATE,
                rsn: "refresh-family-revoked",
              },
        exp: item.exp,
      })),
    ],
    drop: [...sessionLookupRefs(nextSsn), ...familyLookupRefs(fam)],
  };
}

export function createAccessExchangePlan(
  ssn: Ssn,
  input: AccIn,
): Acc {
  const nextSsn: Ssn = {
    ...ssn,
    ajt: input.ajt,
    rat: input.at,
    la: input.at,
    uat: input.at,
    ...(input.bh !== undefined ? { bh: input.bh } : {}),
    ...(input.fp !== undefined ? { fp: input.fp } : {}),
    ...(input.dn !== undefined ? { dn: input.dn } : {}),
    ...(input.loc !== undefined ? { loc: input.loc } : {}),
  };

  return {
    ssn: nextSsn,
    set: [
      {
        key: ssnKey(nextSsn.id),
        val: nextSsn,
        exp: nextSsn.exp,
      },
    ],
    drop:
      ssn.ajt === undefined || ssn.ajt === input.ajt
        ? []
        : [ajtRef(ssn.ajt)],
    ref: createSessionRef(nextSsn),
  };
}

export function createRotatePlan(input: RotIn, ssn: Ssn): Rot {
  const prv: Rtk = {
    ...input.cur,
    st: ROTATED_STATE,
    rid: input.nxt.id,
  };

  const nextSsn: Ssn = {
    ...ssn,
    rat: input.at,
    ajt: input.nxt.jt,
    uat: input.at,
  };

  return {
    ssn: nextSsn,
    prv,
    nxt: input.nxt,
    set: [
      {
        key: ssnKey(nextSsn.id),
        val: nextSsn,
        exp: nextSsn.exp,
      },
      {
        key: rtkKey(prv.id),
        val: prv,
        exp: prv.exp,
      },
      {
        key: rtkKey(input.nxt.id),
        val: input.nxt,
        exp: input.nxt.exp,
      },
    ],
    del: [],
    drop:
      ssn.ajt === undefined || ssn.ajt === nextSsn.ajt
        ? []
        : [ajtRef(ssn.ajt)],
    ref: [...createRef(input.nxt), ...createSessionRef(nextSsn)],
  };
}
