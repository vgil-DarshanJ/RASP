/** Used when PUBLIC_INGESTION_URL is not set (local development on this machine). */
export const DEFAULT_INGESTION_URL = "http://localhost:4000/v1/events";

/**
 * The ingestion URL this backend tells the dashboard and puts into issued
 * credential JSON (`ingestion_url`): PUBLIC_INGESTION_URL, or
 * DEFAULT_INGESTION_URL when it is unset or blank. Set PUBLIC_INGESTION_URL
 * to an address the phone can reach (e.g. http://<PC LAN IP>:4000/v1/events)
 * before issuing a credential for a device.
 */
export function publicIngestionUrl(env: NodeJS.ProcessEnv = process.env): string {
  return env.PUBLIC_INGESTION_URL?.trim() || DEFAULT_INGESTION_URL;
}
