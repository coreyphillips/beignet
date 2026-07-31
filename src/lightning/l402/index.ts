/**
 * L402 (Lightning HTTP 402) client.
 *
 * Consumes L402-gated HTTP APIs: parse the challenge, check the invoice
 * against the macaroon's payment hash commitment, pay under a caller-supplied
 * price cap, and retry with the paid credential. Server-side issuance
 * (macaroon minting, root keys, gating daemon routes) is a later phase.
 *
 * Spec: https://github.com/lightninglabs/L402
 */

export * from './macaroon';
export * from './challenge';
export * from './credentials';
export * from './client';
