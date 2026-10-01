import type { ConnectionOptions, TLSSocket } from 'tls';
import { Tls } from '../types';

const normalizeFingerprint = (fingerprint: string): string =>
	fingerprint.replace(/:/g, '').toUpperCase();

/**
 * Wraps Node's `tls` module so Electrum connections verify the server
 * certificate. Pass the result as `electrumOptions.tls`.
 *
 * rn-electrum-client always dials with `rejectUnauthorized: false`, so the
 * plain `tls` module encrypts the session but accepts any certificate, and an
 * on-path attacker can stand in for the server. The wrapper accepts a
 * connection only when the certificate chains to a trusted CA and matches the
 * host name, or when its SHA-256 fingerprint is one of `fingerprints` (for
 * servers with self-signed certificates). Anything else fails the connect.
 *
 * Node only: under React Native the client builds its TLS socket without
 * calling `connect`, so the wrapper refuses to be created there rather than
 * verify nothing.
 *
 * @param {Tls} tls Node's `tls` module
 * @param {string[]} [fingerprints] SHA-256 certificate fingerprints, hex with
 * or without colons, as printed by `openssl x509 -noout -fingerprint -sha256`
 * @returns {Tls}
 */
export const withTlsVerification = (
	tls: Tls,
	{ fingerprints = [] }: { fingerprints?: string[] } = {}
): Tls => {
	if (typeof process === 'undefined' || process.release?.name !== 'node') {
		throw new Error('withTlsVerification needs Node.js');
	}
	const pinned = new Set(fingerprints.map(normalizeFingerprint));
	for (const fingerprint of pinned) {
		if (!/^[0-9A-F]{64}$/.test(fingerprint)) {
			throw new Error(`Invalid SHA-256 fingerprint: ${fingerprint}`);
		}
	}
	// Only the options form: it is the one rn-electrum-client calls.
	const connect = (
		options: ConnectionOptions,
		secureConnectListener?: () => void
	): TLSSocket => {
		// Verification is decided here rather than by rejectUnauthorized, which
		// would also refuse a pinned self-signed certificate.
		const socket = tls.connect(
			{ ...options, rejectUnauthorized: false },
			() => {
				const fingerprint = socket.getPeerCertificate().fingerprint256;
				if (
					!socket.authorized &&
					!(fingerprint && pinned.has(normalizeFingerprint(fingerprint)))
				) {
					socket.destroy(
						new Error(
							`Electrum server certificate rejected (${socket.authorizationError}), SHA-256 fingerprint ${fingerprint}`
						)
					);
					return;
				}
				secureConnectListener?.();
			}
		);
		return socket;
	};
	return { ...tls, connect } as Tls;
};
