import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import Fastify from "fastify";
import { requestIp, trustedProxySetting } from "../utils/clientIp.js";

// A real HTTP gateway and inner proxy exercise header replacement/append behavior.
// The gateway models Traefik accepting forwarding only from its configured peers.
test("trusted proxy chain rejects spoofed forwarding and Cloudflare headers", async (t) => {
  process.env.TRUSTED_PROXY_CIDRS = "127.0.0.1/32,::1/128,10.0.0.0/8";
  process.env.TRUST_CLOUDFLARE = "true";
  const backend = Fastify({ trustProxy: trustedProxySetting() });
  backend.get("/", (req) => ({ ip: requestIp(req) }));
  await backend.listen({ host: "127.0.0.1", port: 0 });
  t.after(() => backend.close());
  const address = backend.server.address();
  function proxy(target, headers) {
    return http.createServer((req, res) => {
      const upstream = http.request(
        {
          hostname: "127.0.0.1",
          port: target,
          path: "/",
          headers: headers(req),
        },
        (response) => {
          res.writeHead(response.statusCode, response.headers);
          response.pipe(res);
        },
      );
      upstream.on("error", () => {
        res.statusCode = 502;
        res.end();
      });
      req.pipe(upstream);
    });
  }
  const start = (server) =>
    new Promise((resolve) =>
      server.listen(0, "127.0.0.1", () => resolve(server.address().port)),
    );
  const close = (server) => new Promise((resolve) => server.close(resolve));
  const inner = proxy(address.port, (req) => ({
    ...req.headers,
    "x-forwarded-for": `${req.headers["x-forwarded-for"]}, 10.0.0.2`,
  }));
  const innerPort = await start(inner);
  t.after(() => close(inner));
  // Model direct public access: the gateway discards all user-supplied forwarding.
  const direct = proxy(innerPort, (req) => ({
    ...req.headers,
    "x-forwarded-for": "198.51.100.7",
  }));
  const directPort = await start(direct);
  t.after(() => close(direct));
  const response = await fetch(`http://127.0.0.1:${directPort}`, {
    headers: { "x-forwarded-for": "1.2.3.4", "cf-connecting-ip": "8.8.8.8" },
  });
  assert.equal((await response.json()).ip, "198.51.100.7");
  // Model verified Cloudflare ingress. CF replaces CF-Connecting-IP; the
  // gateway may replace XFF, retaining only its actual Cloudflare peer.
  const cloudflare = proxy(innerPort, (req) => ({
    ...req.headers,
    "x-forwarded-for": "172.71.23.168",
    "cf-connecting-ip": "203.0.113.9",
  }));
  const cloudflarePort = await start(cloudflare);
  t.after(() => close(cloudflare));
  const cf = await fetch(`http://127.0.0.1:${cloudflarePort}`, {
    headers: { "x-forwarded-for": "1.2.3.4", "cf-connecting-ip": "8.8.8.8" },
  });
  assert.equal((await cf.json()).ip, "203.0.113.9");
  const untrusted = await backend.inject({
    url: "/",
    remoteAddress: "198.51.100.2",
    headers: {
      "x-forwarded-for": "172.71.23.168",
      "cf-connecting-ip": "8.8.8.8",
    },
  });
  assert.equal(untrusted.json().ip, "198.51.100.2");
  process.env.TRUST_CLOUDFLARE = "false";
  const disabled = await backend.inject({
    url: "/",
    remoteAddress: "10.0.0.3",
    headers: {
      "x-forwarded-for": "172.71.23.168",
      "cf-connecting-ip": "8.8.8.8",
    },
  });
  assert.equal(disabled.json().ip, "172.71.23.168");
});
