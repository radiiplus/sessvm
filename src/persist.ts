import type {
  DelRec,
  Key,
  Kv,
  Ref,
  Rtk,
  SetRec,
  Ssn,
  Store,
} from "./store";
import { createStore } from "./store/svc";

export type Row = Ssn | Rtk;
export type Port = Kv;
export type PutRow = SetRec;
export type DelRow = DelRec;
export type Link = Ref;
export type Slot = Key;

export function pst(port: Port): Store {
  return createStore(port);
}
