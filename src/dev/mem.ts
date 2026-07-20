import {
  isSsn,
  type DelRec,
  type Key,
  type Kv,
  type Ref,
  type Rtk,
  type SetRec,
  type Ssn,
  type Store,
} from "../store";
import { createStore } from "../store/svc";

export type Mode = "dev" | "prod";

export interface MemOpt {
  readonly mode?: Mode;
}

function copyKey(key: Key): Key {
  return {
    pk: key.pk,
    sk: key.sk,
  };
}

function copySsn(ssn: Ssn): Ssn {
  const next: Ssn = {
    id: ssn.id,
    sub: ssn.sub,
    did: ssn.did,
    iss: ssn.iss,
    aud: ssn.aud,
    scp: [...ssn.scp],
    st: ssn.st,
    iat: ssn.iat,
    exp: ssn.exp,
    rat: ssn.rat,
    ...(ssn.dn !== undefined ? { dn: ssn.dn } : {}),
    ...(ssn.loc !== undefined ? { loc: ssn.loc } : {}),
    ...(ssn.la !== undefined ? { la: ssn.la } : {}),
    ...(ssn.ajt !== undefined ? { ajt: ssn.ajt } : {}),
    ...(ssn.bh !== undefined ? { bh: ssn.bh } : {}),
    ...(ssn.fp !== undefined
      ? {
          fp: {
            ua: ssn.fp.ua,
            al: ssn.fp.al,
            ja: ssn.fp.ja,
            ip: ssn.fp.ip,
            ...(ssn.fp.br !== undefined ? { br: ssn.fp.br } : {}),
            ...(ssn.fp.bv !== undefined ? { bv: ssn.fp.bv } : {}),
            ...(ssn.fp.asn !== undefined ? { asn: ssn.fp.asn } : {}),
          },
        }
      : {}),
  };

  if (ssn.uat !== undefined) {
    return {
      ...next,
      uat: ssn.uat,
      ...(ssn.ext !== undefined ? { ext: { ...ssn.ext } } : {}),
    };
  }

  if (ssn.ext !== undefined) {
    return {
      ...next,
      ext: { ...ssn.ext },
    };
  }

  return next;
}

function copyRtk<TState extends Rtk["st"]>(rtk: Rtk<TState>): Rtk<TState> {
  const next: Rtk<TState> = {
    id: rtk.id,
    tk: rtk.tk,
    fid: rtk.fid,
    kid: rtk.kid,
    hd: rtk.hd,
    su: rtk.su,
    sid: rtk.sid,
    jt: rtk.jt,
    bh: rtk.bh,
    st: rtk.st,
    iat: rtk.iat,
    exp: rtk.exp,
    ...(rtk.fp !== undefined
      ? {
          fp: {
            ua: rtk.fp.ua,
            al: rtk.fp.al,
            ja: rtk.fp.ja,
            ip: rtk.fp.ip,
          },
        }
      : {}),
  };

  if (rtk.rid !== undefined) {
    return {
      ...next,
      rid: rtk.rid,
      ...(rtk.rsn !== undefined ? { rsn: rtk.rsn } : {}),
    };
  }

  if (rtk.rsn !== undefined) {
    return {
      ...next,
      rsn: rtk.rsn,
    };
  }

  return next;
}

function copyRow(row: Ssn | Rtk): Ssn | Rtk {
  return isSsn(row) ? copySsn(row) : copyRtk(row);
}

function keyId(key: Key): string {
  return `${key.pk}:${key.sk}`;
}

function readMode(): Mode {
  const env = (
    globalThis as typeof globalThis & {
      process?: {
        env?: {
          NODE_ENV?: string;
        };
      };
    }
  ).process?.env?.NODE_ENV;

  return env === "production" ? "prod" : "dev";
}

class MemKv implements Kv {
  private readonly rows = new Map<string, Ssn | Rtk>();

  private readonly refs = new Map<string, Key>();

  private readonly lists = new Map<string, Key[]>();

  async put(rows: readonly SetRec[]): Promise<void> {
    for (const row of rows) {
      this.rows.set(keyId(row.key), copyRow(row.val));
    }
  }

  async get(key: Key): Promise<Ssn | Rtk | null> {
    const row = this.rows.get(keyId(key));
    return row === undefined ? null : copyRow(row);
  }

  async del(rows: readonly DelRec[]): Promise<void> {
    for (const row of rows) {
      this.rows.delete(keyId(row.key));
    }
  }

  async bind(refs: readonly Ref[]): Promise<void> {
    for (const ref of refs) {
      this.refs.set(ref.val, copyKey(ref.key));

      if (ref.cardinality === "one") {
        this.lists.set(ref.val, [copyKey(ref.key)]);
        continue;
      }

      const items = this.lists.get(ref.val) ?? [];

      if (!items.some((item) => keyId(item) === keyId(ref.key))) {
        items.push(copyKey(ref.key));
        this.lists.set(ref.val, items);
      }
    }
  }

  async read(val: string): Promise<Key | null> {
    const key = this.refs.get(val);
    return key === undefined ? null : copyKey(key);
  }

  async list(val: string): Promise<readonly Key[]> {
    return (this.lists.get(val) ?? []).map((key) => copyKey(key));
  }

  async drop(vals: readonly string[]): Promise<void> {
    for (const val of vals) {
      this.refs.delete(val);
      this.lists.delete(val);
    }
  }
}

export function createMemStore(options: MemOpt = {}): Store {
  const mode = options.mode ?? readMode();

  if (mode !== "dev") {
    throw new Error("The in-memory store is dev-only and is disabled in prod mode.");
  }

  return createStore(new MemKv());
}
