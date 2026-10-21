import * as tls from 'tls';
import { Tls } from '../types/electrum';
import { withTlsVerification } from '../utils/tls-verification';

/**
 * Electrum TLS certificate verification for the daemon (issue #1776). Off by
 * default: a TLS Electrum connection is then encrypted but accepts any
 * certificate, because rn-electrum-client dials with rejectUnauthorized: false.
 */
export interface ElectrumTlsConfig {
	/**
	 * Verify Electrum TLS certificates (default false). Every TLS connection
	 * the wallet opens, to the configured server or to a public fallback, is
	 * accepted only when its certificate chains to a trusted CA and matches the
	 * host name, or when its SHA-256 fingerprint is in electrumTlsFingerprints.
	 */
	electrumTlsVerify?: boolean;
	/**
	 * SHA-256 fingerprints of Electrum certificates to accept without a CA, for
	 * servers with self-signed certificates. Hex with or without colons, as
	 * printed by `openssl x509 -noout -fingerprint -sha256`. Needs
	 * electrumTlsVerify.
	 */
	electrumTlsFingerprints?: string[];
}

/**
 * BEIGNET_ELECTRUM_TLS_VERIFY. A security switch, so anything but true, false
 * or empty refuses startup: a typo must not leave verification silently off.
 * Empty counts as unset, for compose files that pass an optional variable
 * through.
 */
export function electrumTlsVerifyEnv(): boolean | undefined {
	const value = process.env.BEIGNET_ELECTRUM_TLS_VERIFY?.trim();
	if (!value) return undefined;
	if (value === 'true') return true;
	if (value === 'false') return false;
	throw new Error('BEIGNET_ELECTRUM_TLS_VERIFY must be exactly true or false');
}

/** BEIGNET_ELECTRUM_TLS_FINGERPRINTS, comma separated. Empty counts as unset. */
export function electrumTlsFingerprintsEnv(): string[] | undefined {
	const fingerprints = process.env.BEIGNET_ELECTRUM_TLS_FINGERPRINTS?.split(',')
		.map((fingerprint) => fingerprint.trim())
		.filter(Boolean);
	return fingerprints?.length ? fingerprints : undefined;
}

/**
 * Config-only checks, run before the node boots. A malformed fingerprint fails
 * with the wrapper's own error, and pinned fingerprints without verification
 * are refused rather than ignored: an operator who pinned a certificate
 * believes the connection is checked.
 */
export function validateElectrumTlsConfig(config: ElectrumTlsConfig): void {
	if (
		config.electrumTlsVerify !== undefined &&
		typeof config.electrumTlsVerify !== 'boolean'
	) {
		throw new Error('electrumTlsVerify must be a boolean');
	}
	const fingerprints = config.electrumTlsFingerprints;
	if (fingerprints === undefined) return;
	if (
		!Array.isArray(fingerprints) ||
		fingerprints.some((value) => typeof value !== 'string')
	) {
		throw new Error(
			'electrumTlsFingerprints must be an array of SHA-256 fingerprints'
		);
	}
	if (fingerprints.length > 0 && config.electrumTlsVerify !== true) {
		throw new Error(
			'electrumTlsFingerprints needs electrumTlsVerify: true (BEIGNET_ELECTRUM_TLS_VERIFY=true); without it no certificate is checked'
		);
	}
	withTlsVerification(tls, { fingerprints });
}

/**
 * The tls module the wallet's Electrum client dials with. With verification
 * on, a host that was resolved before dialing keeps its configured name for
 * the certificate check, so `dialedHost` is the address actually dialed and
 * `configuredHost` the name the operator gave.
 */
export function electrumTlsModule(
	config: ElectrumTlsConfig,
	dialedHost: string,
	configuredHost: string
): Tls {
	if (config.electrumTlsVerify !== true) return tls;
	return withTlsVerification(tls, {
		fingerprints: config.electrumTlsFingerprints,
		servernames:
			dialedHost !== configuredHost ? { [dialedHost]: configuredHost } : {}
	});
}
