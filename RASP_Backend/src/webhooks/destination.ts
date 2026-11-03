import dns from "node:dns";
import net from "node:net";

/**
 * Where webhooks may be delivered (F-08): public HTTPS endpoints only.
 *
 * The backend makes the request, so a URL pointing at a private, loopback,
 * link-local or other special address would let any dashboard user make the
 * server call its own internal network (for example a cloud metadata
 * service). Addresses are checked when the URL is saved and again on every
 * delivery, against the address the connection actually uses (the DNS
 * answer is checked inside the socket's own lookup, so a name cannot
 * resolve to a public address for the check and a private one for the
 * connection). Redirects are never followed.
 *
 * Development only: WEBHOOK_ALLOW_PRIVATE_DESTINATIONS=1 allows http:// and
 * private addresses (a receiver on this PC or the LAN). Ignored when
 * NODE_ENV=production.
 */

const BLOCKED = new net.BlockList();
for (const [address, prefix] of [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16],
  ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.88.99.0", 24], ["192.168.0.0", 16],
  ["198.18.0.0", 15], ["198.51.100.0", 24], ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
] as const) BLOCKED.addSubnet(address, prefix, "ipv4");
for (const [address, prefix] of [
  ["::", 128], ["::1", 128], ["64:ff9b:1::", 48], ["100::", 64], ["2001::", 23], ["2001:db8::", 32],
  ["2002::", 16], ["fc00::", 7], ["fe80::", 10], ["fec0::", 10], ["ff00::", 8],
] as const) BLOCKED.addSubnet(address, prefix, "ipv6");

/** IPv4 inside an IPv4-mapped (::ffff:a.b.c.d) or NAT64 (64:ff9b::a.b.c.d) IPv6 address. */
function embeddedIpv4(address: string): string | null {
  const lower = address.toLowerCase();
  const dotted = lower.match(/^(?:::ffff:|64:ff9b::)(\d+\.\d+\.\d+\.\d+)$/);
  if (dotted) return dotted[1];
  const hex = lower.match(/^(?:::ffff:|64:ff9b::)([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (hex) {
    const hi = parseInt(hex[1], 16);
    const lo = parseInt(hex[2], 16);
    return `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
  }
  return null;
}

/** `true` for an address a webhook must never reach. */
export function isBlockedAddress(address: string): boolean {
  const family = net.isIP(address);
  if (family === 4) return BLOCKED.check(address, "ipv4");
  if (family === 6) {
    const v4 = embeddedIpv4(address);
    if (v4 !== null) return BLOCKED.check(v4, "ipv4");
    return BLOCKED.check(address, "ipv6");
  }
  return true; // not an IP address at all
}

export function privateDestinationsAllowed(): boolean {
  return process.env.WEBHOOK_ALLOW_PRIVATE_DESTINATIONS === "1" && process.env.NODE_ENV !== "production";
}

export type DestinationError =
  | "WEBHOOK_URL_INVALID"
  | "WEBHOOK_URL_NOT_HTTPS"
  | "WEBHOOK_URL_HAS_CREDENTIALS"
  | "WEBHOOK_URL_PRIVATE_ADDRESS"
  | "WEBHOOK_URL_UNRESOLVABLE";

type Resolver = (hostname: string) => Promise<Array<{ address: string; family: number }>>;

/** DNS used by [checkDestination]; tests replace it. */
export const destinationDns: { resolve: Resolver } = {
  resolve: (hostname) => dns.promises.lookup(hostname, { all: true, verbatim: true }),
};

function hostOf(url: URL): string {
  return url.hostname.startsWith("[") ? url.hostname.slice(1, -1) : url.hostname;
}

/** Checks a webhook URL before it is saved: scheme, no user:password, every resolved address public. */
export async function checkDestination(raw: string): Promise<DestinationError | null> {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return "WEBHOOK_URL_INVALID";
  }
  const allowPrivate = privateDestinationsAllowed();
  if (url.protocol !== "https:" && !(allowPrivate && url.protocol === "http:")) return "WEBHOOK_URL_NOT_HTTPS";
  if (url.username || url.password) return "WEBHOOK_URL_HAS_CREDENTIALS";
  if (allowPrivate) return null;
  const host = hostOf(url);
  if (net.isIP(host)) return isBlockedAddress(host) ? "WEBHOOK_URL_PRIVATE_ADDRESS" : null;
  let addresses: Array<{ address: string }>;
  try {
    addresses = await destinationDns.resolve(host);
  } catch {
    return "WEBHOOK_URL_UNRESOLVABLE";
  }
  if (addresses.length === 0) return "WEBHOOK_URL_UNRESOLVABLE";
  return addresses.some((a) => isBlockedAddress(a.address)) ? "WEBHOOK_URL_PRIVATE_ADDRESS" : null;
}

/**
 * `lookup` for http(s).request: resolves like the default one, but fails the
 * connection when any answer is a blocked address.
 */
export function guardedLookup(
  hostname: string,
  options: dns.LookupOptions,
  callback: (err: NodeJS.ErrnoException | null, address: string | dns.LookupAddress[], family?: number) => void,
): void {
  dns.lookup(hostname, { ...options, all: true }, (err, addresses) => {
    if (err) return callback(err, "", 0);
    const list = addresses as dns.LookupAddress[];
    if (!privateDestinationsAllowed() && (list.length === 0 || list.some((a) => isBlockedAddress(a.address)))) {
      const blocked = new Error(`webhook destination ${hostname} resolves to a private or reserved address`) as NodeJS.ErrnoException;
      blocked.code = "WEBHOOK_URL_PRIVATE_ADDRESS";
      return callback(blocked, "", 0);
    }
    if (options.all) return callback(null, list);
    callback(null, list[0].address, list[0].family);
  });
}
