/** Used when PUBLIC_INGESTION_URL is unset; reachable by office-LAN devices. */
export const DEFAULT_INGESTION_URL = "http://192.168.2.208:4444/v1/events";

/**
 * The ingestion URL this backend tells the dashboard and puts into issued
 * credential JSON (`ingestion_url`): PUBLIC_INGESTION_URL, or
 * DEFAULT_INGESTION_URL when it is unset or blank. Set PUBLIC_INGESTION_URL
 * to an address the phone can reach before issuing a credential for a device.
 */
export function publicIngestionUrl(env: NodeJS.ProcessEnv = process.env): string {
  return env.PUBLIC_INGESTION_URL?.trim() || DEFAULT_INGESTION_URL;
}
