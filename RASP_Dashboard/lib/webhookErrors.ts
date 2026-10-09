/** Dashboard wording for the backend's webhook error codes (see BE webhooks/destination.ts and auth/roles.ts). */
const MESSAGES: Record<string, string> = {
  WEBHOOK_URL_INVALID: "That is not a valid URL.",
  WEBHOOK_URL_NOT_HTTPS: "The webhook URL must start with https://.",
  WEBHOOK_URL_HAS_CREDENTIALS: "Remove the user name and password from the URL; deliveries are authenticated by the signing secret.",
  WEBHOOK_URL_PRIVATE_ADDRESS: "The URL points to a private, local or reserved address. Use a public HTTPS endpoint.",
  WEBHOOK_URL_UNRESOLVABLE: "The host name in the URL could not be found.",
  FORBIDDEN_ROLE: "Only an owner or admin can change webhooks.",
};

export function webhookErrorMessage(code: unknown, fallback: string): string {
  return typeof code === "string" && code in MESSAGES ? MESSAGES[code] : fallback;
}
