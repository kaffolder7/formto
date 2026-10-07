import proxyAddr from "@fastify/proxy-addr";
import net from "node:net";

// Cloudflare's published proxy networks: https://www.cloudflare.com/ips/
// Only consult CF-Connecting-IP when the nearest non-local peer is Cloudflare.
export const CLOUDFLARE_CIDRS = [
  "173.245.48.0/20",
  "103.21.244.0/22",
  "103.22.200.0/22",
  "103.31.4.0/22",
  "141.101.64.0/18",
  "108.162.192.0/18",
  "190.93.240.0/20",
  "188.114.96.0/20",
  "197.234.240.0/22",
  "198.41.128.0/17",
  "162.158.0.0/15",
  "104.16.0.0/13",
  "104.24.0.0/14",
  "172.64.0.0/13",
  "131.0.72.0/22",
  "2400:cb00::/32",
  "2606:4700::/32",
  "2803:f800::/32",
  "2405:b500::/32",
  "2405:8100::/32",
  "2a06:98c0::/29",
  "2c0f:f248::/32",
];
const isCloudflare = proxyAddr.compile(CLOUDFLARE_CIDRS);
export function trustedProxySetting() {
  const cidrs = (process.env.TRUSTED_PROXY_CIDRS || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (!cidrs.length) return false;
  // Validate at startup; never silently broaden an invalid trust configuration.
  return proxyAddr.compile(cidrs);
}
export function requestIp(request) {
  const peer = request.ip || request.raw?.socket?.remoteAddress || "127.0.0.1";
  const cloudflareIp = request.headers["cf-connecting-ip"];
  if (
    process.env.TRUST_CLOUDFLARE === "true" &&
    net.isIP(peer) &&
    isCloudflare(peer) &&
    typeof cloudflareIp === "string" &&
    net.isIP(cloudflareIp)
  )
    return cloudflareIp;
  return peer;
}
