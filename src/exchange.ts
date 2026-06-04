import {
  Ssv,
  type ExchangeIn,
  type ExchangeOut,
  type SessionCfg,
  type Store,
} from "./index";

export type ExchangeCfg = SessionCfg;

export class Xcg {
  private readonly svc: Ssv;

  constructor(store: Store, cfg: ExchangeCfg) {
    this.svc = new Ssv(store, cfg);
  }

  async run(input: ExchangeIn): Promise<ExchangeOut> {
    return this.svc.exchange(input);
  }
}

export function xcg(
  store: Store,
  cfg: ExchangeCfg,
): Xcg {
  return new Xcg(store, cfg);
}
