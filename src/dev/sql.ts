import { DatabaseSync } from "node:sqlite";
import type { DelRec, Key, Kv, Ref, Rtk, SetRec, Ssn } from "../store";
import { createStore } from "../store/svc";
import type { Store } from "../store";

export interface SqlOpt {
  readonly path?: string;
}

function keyId(key: Key): string {
  return `${key.pk}:${key.sk}`;
}

function encode(row: Ssn | Rtk): string {
  return JSON.stringify(row);
}

function decode(value: string): Ssn | Rtk {
  return JSON.parse(value) as Ssn | Rtk;
}

function splitKey(id: string): Key {
  const index = id.indexOf(":");

  if (index < 0) {
    throw new Error("Invalid stored key id.");
  }

  return {
    pk: id.slice(0, index),
    sk: id.slice(index + 1),
  };
}

export class SqlKv implements Kv {
  private readonly db: DatabaseSync;

  constructor(options: SqlOpt = {}) {
    this.db = new DatabaseSync(options.path ?? ":memory:");
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS rows (
        id TEXT PRIMARY KEY,
        pk TEXT NOT NULL,
        sk TEXT NOT NULL,
        val TEXT NOT NULL,
        exp INTEGER
      );
      CREATE TABLE IF NOT EXISTS refs (
        val TEXT NOT NULL,
        key_id TEXT NOT NULL,
        PRIMARY KEY (val, key_id)
      );
      CREATE INDEX IF NOT EXISTS refs_val_idx ON refs (val);
    `);
  }

  async put(rows: readonly SetRec[]): Promise<void> {
    const stmt = this.db.prepare(`
      INSERT INTO rows (id, pk, sk, val, exp)
      VALUES (?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        pk = excluded.pk,
        sk = excluded.sk,
        val = excluded.val,
        exp = excluded.exp
    `);

    for (const row of rows) {
      stmt.run(
        keyId(row.key),
        row.key.pk,
        row.key.sk,
        encode(row.val),
        row.exp ?? null,
      );
    }
  }

  async get(key: Key): Promise<Ssn | Rtk | null> {
    const row = this.db
      .prepare("SELECT val FROM rows WHERE id = ?")
      .get(keyId(key)) as { val: string } | undefined;

    return row === undefined ? null : decode(row.val);
  }

  async del(rows: readonly DelRec[]): Promise<void> {
    const stmt = this.db.prepare("DELETE FROM rows WHERE id = ?");

    for (const row of rows) {
      stmt.run(keyId(row.key));
    }
  }

  async bind(refs: readonly Ref[]): Promise<void> {
    const drop = this.db.prepare("DELETE FROM refs WHERE val = ?");
    const stmt = this.db.prepare(`
      INSERT OR IGNORE INTO refs (val, key_id)
      VALUES (?, ?)
    `);

    for (const ref of refs) {
      if (ref.cardinality === "one") {
        drop.run(ref.val);
      }

      stmt.run(ref.val, keyId(ref.key));
    }
  }

  async read(val: string): Promise<Key | null> {
    const row = this.db
      .prepare("SELECT key_id FROM refs WHERE val = ? ORDER BY key_id DESC LIMIT 1")
      .get(val) as { key_id: string } | undefined;

    return row === undefined ? null : splitKey(row.key_id);
  }

  async list(val: string): Promise<readonly Key[]> {
    const rows = this.db
      .prepare("SELECT key_id FROM refs WHERE val = ? ORDER BY key_id DESC")
      .all(val) as { key_id: string }[];

    return rows.map((row) => splitKey(row.key_id));
  }

  async drop(vals: readonly string[]): Promise<void> {
    const stmt = this.db.prepare("DELETE FROM refs WHERE val = ?");

    for (const val of vals) {
      stmt.run(val);
    }
  }

  close(): void {
    this.db.close();
  }
}

export function sql(options: SqlOpt = {}): Store {
  return createStore(new SqlKv(options));
}
