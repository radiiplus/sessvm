import {
  adp,
  asn,
  dvc,
  fpp,
  fpx,
  rlp,
  stp,
  maskIpPrefix,
  type DeviceFingerprint,
  type FingerprintExtractor,
  type FingerprintVerdict,
  type RequestLike,
} from "../src";

const request: RequestLike = {
  headers: {
    get(name: string) {
      switch (name.toLowerCase()) {
        case "user-agent":
          return "Mozilla/5.0 Example";
        case "accept-language":
          return "en-US,en;q=0.9";
        default:
          return null;
      }
    },
  },
  ip: "203.0.113.42",
  tls: {
    ja3: "771,4865-4866-4867,0-11-10,29-23-24,0",
  },
};

const extractor: FingerprintExtractor = fpx();
const deviceFingerprint: DeviceFingerprint = dvc(request);
const strictPolicy = stp();
const relaxedPolicy = rlp();
const adaptivePolicy = adp(true);
const verdict: FingerprintVerdict = fpp().compare(
  deviceFingerprint,
  dvc({
    ...request,
    ip: "203.0.113.55",
  }),
);
const strictVerdict: FingerprintVerdict = fpp({
  mode: "STRICT",
}).compare(
  asn(deviceFingerprint, "as15169"),
  asn(
    dvc({
      ...request,
      ip: "203.0.113.55",
    }),
    "as15169",
  ),
);
const adaptiveVerdict: FingerprintVerdict = fpp({
  mode: "ADAPTIVE",
  stable: true,
}).compare(
  asn(deviceFingerprint, "as15169"),
  asn(
    dvc({
      ...request,
      headers: {
        get(name: string) {
          switch (name.toLowerCase()) {
            case "user-agent":
              return "Mozilla/5.0 Chrome/126.0 Example";
            case "accept-language":
              return "en-US,en;q=0.9";
            default:
              return null;
          }
        },
      },
    }),
    "as15169",
  ),
);
const maskedIpv4 = maskIpPrefix("203.0.113.42");
const maskedIpv6 = maskIpPrefix("2001:0db8:85a3:0000:0000:8a2e:0370:7334");

void extractor.extract(request);
void strictPolicy.compare(deviceFingerprint, deviceFingerprint);
void relaxedPolicy.compare(deviceFingerprint, deviceFingerprint);
void adaptivePolicy.compare(deviceFingerprint, deviceFingerprint);

if (deviceFingerprint.ua.length === 0) {
  throw new Error("Fingerprint extraction should hash the user agent.");
}

if (deviceFingerprint.al !== "en-us,en;q=0.9") {
  throw new Error("Accept-Language should be normalized.");
}

if (deviceFingerprint.ja === null) {
  throw new Error("JA3 should be retained when available.");
}

if (maskedIpv4 !== "203.0.113.0/24") {
  throw new Error("IPv4 addresses should be reduced to a /24 prefix.");
}

if (maskedIpv6 !== "2001:0db8:85a3:0000::/64") {
  throw new Error("IPv6 addresses should be reduced to a /64 prefix.");
}

if (!verdict.ok) {
  throw new Error("Default fingerprint policy should tolerate IP movement within the same prefix.");
}

if (strictVerdict.ok) {
  throw new Error("Strict fingerprint policy should reject any exact-signal deviation.");
}

if (!adaptiveVerdict.ok) {
  throw new Error("Adaptive fingerprint policy should accept stable-family browser drift.");
}
