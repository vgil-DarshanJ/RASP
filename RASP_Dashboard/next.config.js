/** @type {import('next').NextConfig} */
const nextConfig = {
  // This dev server is reached over the LAN (e.g. from a phone/device
  // running the Flutter trial app's host machine) at the box's real IP,
  // not just localhost — Next 16 blocks cross-origin dev requests (HMR,
  // RSC fetches) by default, so that IP must be explicitly allow-listed
  // or the UI loads but hot-reload/data requests silently fail.
  allowedDevOrigins: ["192.168.2.208"],
  // Production (deploy/, BE repository): NEXT_OUTPUT=export builds plain
  // static files that the HTTPS proxy serves — every page is a client page,
  // so no Node server is needed in front of users.
  ...(process.env.NEXT_OUTPUT === "export" ? { output: "export" } : {}),
  // Laptop testing against the office backend: DEV_API_PROXY=http://192.168.2.208:4444
  // with NEXT_PUBLIC_API_BASE_URL=http://localhost:<port> sends /v1/* through
  // this dev server, so the session cookie is same-site and CORS is not needed.
  ...(process.env.DEV_API_PROXY
    ? { rewrites: async () => [{ source: "/v1/:path*", destination: `${process.env.DEV_API_PROXY}/v1/:path*` }] }
    : {}),
};

module.exports = nextConfig;
