import { createHmac, timingSafeEqual } from "node:crypto";
import type { BindMac, Mac, MacKey } from "../tokens";

function toBuffer(data: string): Buffer {
  return Buffer.from(data, "utf8");
}

function toHex(data: string, key: Uint8Array): string {
  return createHmac("sha256", Buffer.from(key))
    .update(data, "utf8")
    .digest("hex");
}

export const nodeMac: Mac = {
  async sign(data: string, key: MacKey): Promise<string> {
    return toHex(data, key.sec);
  },

  async verify(data: string, sig: string, key: MacKey): Promise<boolean> {
    const actual = toHex(data, key.sec);
    const expectedBuffer = toBuffer(sig);
    const actualBuffer = toBuffer(actual);

    if (expectedBuffer.length !== actualBuffer.length) {
      return false;
    }

    return timingSafeEqual(expectedBuffer, actualBuffer);
  },
};

export const nodeBindMac: BindMac = {
  async sign(data: string, key: Uint8Array): Promise<string> {
    return toHex(data, key);
  },
};
