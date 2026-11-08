import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { getLoginLockoutKey } from "../../../src/server/auth/loginPeer";
import {
  AUTHZ_HEADER_TRUSTED_CLIENT_IP,
  AUTHZ_HEADER_TRUSTED_PEER_IP,
} from "../../../src/server/authz/headers";

const saved = process.env.OMNIROUTE_PEER_STAMP_TOKEN;
afterEach(() => {
  if (saved === undefined) delete process.env.OMNIROUTE_PEER_STAMP_TOKEN;
  else process.env.OMNIROUTE_PEER_STAMP_TOKEN = saved;
});

function req(headers: Record<string, string>): Request {
  return new Request("http://example.test/api/auth/login", { method: "POST", headers });
}

describe("getLoginLockoutKey", () => {
  it("keys visitors behind a trusted proxy by their own address", () => {
    process.env.OMNIROUTE_PEER_STAMP_TOKEN = "t";
    const a = req({
      [AUTHZ_HEADER_TRUSTED_PEER_IP]: "127.0.0.1",
      [AUTHZ_HEADER_TRUSTED_CLIENT_IP]: "203.0.113.5",
    });
    const b = req({
      [AUTHZ_HEADER_TRUSTED_PEER_IP]: "127.0.0.1",
      [AUTHZ_HEADER_TRUSTED_CLIENT_IP]: "198.51.100.9",
    });
    assert.equal(getLoginLockoutKey(a, null), "203.0.113.5");
    assert.notEqual(getLoginLockoutKey(a, null), getLoginLockoutKey(b, null));
  });

  it("falls back to the peer, then one shared key, never to a forwarded address", () => {
    process.env.OMNIROUTE_PEER_STAMP_TOKEN = "t";
    assert.equal(
      getLoginLockoutKey(req({ [AUTHZ_HEADER_TRUSTED_PEER_IP]: "10.0.0.2" }), "1.2.3.4"),
      "10.0.0.2"
    );
    assert.equal(getLoginLockoutKey(req({}), "1.2.3.4"), "__unknown_peer__");
  });
});
