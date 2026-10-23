/**
 * The wallet_data keys daemon state is kept under. Here rather than in
 * auth.ts and webhooks.ts so BeignetNode, which carries them across a
 * capsule restore, does not load the daemon's HTTP modules.
 */

/** wallet_data key under which auth-key overrides are persisted. The colon
 *  segments can never collide with on-chain wallet keys, which always end in
 *  an IWalletData field name ("<wallet>-<network>-<field>"). */
export const AUTH_KEY_OVERRIDES_STORAGE_KEY = 'daemon:auth-key-overrides:v1';

/** wallet_data key the daemon keeps raw webhook HMAC secrets under. */
export const WEBHOOK_SECRETS_STORAGE_KEY = 'daemon:webhook-secrets:v1';
