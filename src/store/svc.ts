import {
  ajtRef,
  createAccessExchangePlan,
  createRef,
  createFamilyRevokePlan,
  createSessionRef,
  createReusePlan,
  createRevokePlan,
  createRotatePlan,
  createSessionPlan,
  devRef,
  fidRef,
  isRtk,
  isSsn,
  lss,
  rtkRef,
  sidRef,
  ssnKey,
  usrRef,
  type CrtIn,
  type AccessHit,
  type DevIn,
  type GetIn,
  type Hit,
  type Kv,
  type Lst,
  type LstIn,
  type Reu,
  type ReuIn,
  type Rev,
  type RevIn,
  type Rot,
  type RotIn,
  type Store,
} from "../store";

export function createStore(kv: Kv): Store {
  return {
    kv,

    async createSession(input: CrtIn) {
      const plan = createSessionPlan(input);
      await kv.put(plan.set);
      await kv.bind(plan.ref);
      return plan;
    },

    async getSessionByRefreshToken(input: GetIn): Promise<Hit | null> {
      const tokenKey = await kv.read(rtkRef(input.tk));

      if (tokenKey === null) {
        return null;
      }

      const tokenRow = await kv.get(tokenKey);

      if (tokenRow === null || !isRtk(tokenRow)) {
        return null;
      }

      const sessionRow = await kv.get(ssnKey(tokenRow.sid));

      if (sessionRow === null || !isSsn(sessionRow)) {
        return null;
      }

      return {
        ssn: sessionRow,
        rtk: tokenRow,
      };
    },

    async getSessionByAccessToken(input): Promise<AccessHit | null> {
      const sessionKey = await kv.read(ajtRef(input.jt));

      if (sessionKey === null) {
        return null;
      }

      const sessionRow = await kv.get(sessionKey);

      if (sessionRow === null || !isSsn(sessionRow)) {
        return null;
      }

      return {
        ssn: sessionRow,
      };
    },

    async getSessionByDevice(input: DevIn): Promise<AccessHit | null> {
      const sessionKey = await kv.read(devRef(input.sub, input.did));

      if (sessionKey === null) {
        return null;
      }

      const sessionRow = await kv.get(sessionKey);

      if (sessionRow === null || !isSsn(sessionRow)) {
        return null;
      }

      return {
        ssn: sessionRow,
      };
    },

    async listActiveSessions(input: LstIn): Promise<readonly Lst[]> {
      const sessionKeys = await kv.list(usrRef(input.sub));
      const rows = await Promise.all(
        sessionKeys.map(async (key) => kv.get(key)),
      );
      const sessions = rows.filter((row) => row !== null && isSsn(row));
      return lss(sessions);
    },

    async revokeSession(input: RevIn): Promise<Rev | null> {
      const sessionRow = await kv.get(ssnKey(input.sid));

      if (sessionRow === null || !isSsn(sessionRow)) {
        return null;
      }

      const tokenKey = await kv.read(sidRef(input.sid));

      if (tokenKey === null) {
        return null;
      }

      const tokenRow = await kv.get(tokenKey);

      if (tokenRow === null || !isRtk(tokenRow)) {
        return null;
      }

      const plan = createRevokePlan(sessionRow, tokenRow, input.at, input.rsn);
      await kv.put(plan.set);
      await kv.bind([...createRef(plan.rtk), ...createSessionRef(plan.ssn)]);
      return plan;
    },

    async revokeSessionFamily(input) {
      const sessionRow = await kv.get(ssnKey(input.sid));

      if (sessionRow === null || !isSsn(sessionRow)) {
        return null;
      }

      const tokenKey = await kv.read(sidRef(input.sid));

      if (tokenKey === null) {
        return null;
      }

      const tokenRow = await kv.get(tokenKey);

      if (tokenRow === null || !isRtk(tokenRow)) {
        return null;
      }

      const familyKeys = await kv.list(fidRef(tokenRow.fid));
      const familyRows = await Promise.all(
        familyKeys.map(async (key) => kv.get(key)),
      );
      const family = familyRows.filter((row) => row !== null && isRtk(row));
      const plan = createFamilyRevokePlan(sessionRow, family, input.at, input.rsn);
      await kv.put(plan.set);
      await kv.bind(createSessionRef(plan.ssn));
      return plan;
    },

    async revokeRefreshFamily(input: ReuIn): Promise<Reu | null> {
      const sessionRow = await kv.get(ssnKey(input.sid));

      if (sessionRow === null || !isSsn(sessionRow)) {
        return null;
      }

      const tokenKey = await kv.read(rtkRef(input.tk));

      if (tokenKey === null) {
        return null;
      }

      const tokenRow = await kv.get(tokenKey);

      if (tokenRow === null || !isRtk(tokenRow)) {
        return null;
      }

      const familyKeys = await kv.list(fidRef(tokenRow.fid));
      const familyRows = await Promise.all(
        familyKeys.map(async (key) => kv.get(key)),
      );
      const family = familyRows.filter((row) => row !== null && isRtk(row));
      const plan = createReusePlan(sessionRow, tokenRow, input.at, family);
      await kv.put(plan.set);
      await kv.bind([...createRef(plan.rtk), ...createSessionRef(plan.ssn)]);
      return plan;
    },

    async exchangeAccessToken(input) {
      const sessionRow = await kv.get(ssnKey(input.sid));

      if (sessionRow === null || !isSsn(sessionRow)) {
        return null;
      }

      const plan = createAccessExchangePlan(sessionRow, input);
      await kv.put(plan.set);
      await kv.bind(plan.ref);
      return plan;
    },

    async rotateRefreshToken(input: RotIn): Promise<Rot> {
      const sessionRow = await kv.get(ssnKey(input.cur.sid));

      if (sessionRow === null || !isSsn(sessionRow)) {
        throw new Error("Cannot rotate a refresh token without a stored session.");
      }

      const plan = createRotatePlan(input, sessionRow);
      await kv.put(plan.set);
      await kv.bind(plan.ref);

      if (plan.del.length > 0) {
        await kv.del(plan.del);
      }

      return plan;
    },
  };
}
