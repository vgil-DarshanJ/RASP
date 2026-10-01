/** @type {import('next').NextConfig} */
const nextConfig = {
  // This dev server is reached over the LAN (e.g. from a phone/device
  // running the Flutter trial app's host machine) at the box's real IP,
  // not just localhost — Next 16 blocks cross-origin dev requests (HMR,
  // RSC fetches) by default, so that IP must be explicitly allow-listed
  // or the UI loads but hot-reload/data requests silently fail.
  allowedDevOrigins: ["192.168.2.208"],
};

module.exports = nextConfig;
