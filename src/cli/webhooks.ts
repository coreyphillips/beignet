/**
 * WebhookManager: Manages webhook registrations and dispatches events.
 * Supports optional persistent storage — when storage is provided, webhooks
 * survive daemon restarts. Without storage, falls back to ephemeral (in-memory).
 * HMAC-SHA256 signing via optional secret for payload verification.
 */

import * as http from 'http';
import * as https from 'https';
import * as crypto from 'crypto';
import { BeignetError } from './errors';
import { isPrivateNetworkUrl } from '../lightning/l402';

/** wallet_data key the daemon keeps raw webhook HMAC secrets under. */
export const WEBHOOK_SECRETS_STORAGE_KEY = 'daemon:webhook-secrets:v1';

/**
 * Why a URL cannot be a webhook target, or null when it can. Only http and
 * https are delivered. A loopback, private or link-local host is reachable
 * only from this machine, so it takes the same opt-in as POST /l402/fetch.
 */
export function webhookTargetRefusal(
	url: string,
	allowPrivateNetwork: boolean
): BeignetError | null {
	let protocol: string;
	try {
		protocol = new URL(url).protocol;
	} catch {
		return new BeignetError('INVALID_PARAMS', 'Webhook url is not a valid URL');
	}
	if (protocol !== 'http:' && protocol !== 'https:') {
		return new BeignetError(
			'INVALID_PARAMS',
			`Webhook url must be http or https, got ${protocol}`
		);
	}
	if (!allowPrivateNetwork && isPrivateNetworkUrl(url)) {
		return new BeignetError(
			'PRIVATE_NETWORK_REFUSED',
			'Webhook url names a private, loopback, or link-local host; pass allowPrivateNetwork to permit it'
		);
	}
	return null;
}

export interface WebhookRegistration {
	id: string;
	url: string;
	events: string[];
	secret?: string;
	createdAt: number;
}

export interface IWebhookStorage {
	saveWebhook(
		id: string,
		url: string,
		events: string[],
		secretHash?: string,
		createdAt?: number
	): void;
	deleteWebhook(id: string): void;
	deleteAllWebhooks(): void;
	loadAllWebhooks(): Array<{
		id: string;
		url: string;
		events: string[];
		secretHash?: string;
		createdAt: number;
	}>;
	/**
	 * Raw HMAC secrets by webhook id, so deliveries after a restart are still
	 * signed. Optional: without them a secret lasts for the process only.
	 * Back them with storage that is encrypted at rest; the webhook rows are
	 * not.
	 */
	saveWebhookSecrets?(secrets: Record<string, string>): void;
	loadWebhookSecrets?(): Record<string, string> | null;
}

interface WebhookEntry extends WebhookRegistration {
	// internal: secretHash for storage (not the raw secret)
	secretHash?: string;
}

function sha256Hex(value: string): string {
	return crypto.createHash('sha256').update(value).digest('hex');
}

/**
 * The event without a top-level preimage (payment:sent, payment:received).
 * A webhook URL is only as private as whoever registered it, and plain http
 * is allowed; the preimage stays available from GET /payment.
 */
function withoutPreimage(data: unknown): unknown {
	if (
		typeof data !== 'object' ||
		data === null ||
		Array.isArray(data) ||
		!('preimage' in data)
	) {
		return data;
	}
	const copy: Record<string, unknown> = { ...data };
	delete copy.preimage;
	return copy;
}

const DELIVERY_TIMEOUT_MS = 5000;
const RETRY_DELAY_MS = 2000;

export class WebhookManager {
	private webhooks: Map<string, WebhookEntry> = new Map();
	private holdDeliveries = new Map<string, Map<string, Promise<void>>>();
	private storage: IWebhookStorage | null;

	constructor(storage?: IWebhookStorage) {
		this.storage = storage ?? null;

		// Restore persisted webhooks
		if (this.storage) {
			try {
				const secrets = this.loadSecrets();
				for (const row of this.storage.loadAllWebhooks()) {
					const secret = secrets[row.id];
					this.webhooks.set(row.id, {
						id: row.id,
						url: row.url,
						events: row.events,
						// A registration stored before secrets were kept has only
						// the hash, and delivers unsigned until re-registered.
						secret:
							typeof secret === 'string' && sha256Hex(secret) === row.secretHash
								? secret
								: undefined,
						secretHash: row.secretHash,
						createdAt: row.createdAt
					});
				}
			} catch {
				// Storage failure should not prevent startup
			}
		}
	}

	/**
	 * Register a new webhook.
	 * @param url - The URL to POST events to
	 * @param events - Event types to subscribe to (e.g. ['payment:received', 'channel:ready'])
	 * @param secret - Optional secret for HMAC-SHA256 signing
	 * @returns The webhook registration
	 */
	register(
		url: string,
		events: string[],
		secret?: string
	): WebhookRegistration {
		if (!url || !events || events.length === 0) {
			throw new Error('url and at least one event type are required');
		}
		// Any other scheme was posted as plain http to the URL's host, or to
		// localhost:80 when it had none (file:).
		const refusal = webhookTargetRefusal(url, true);
		if (refusal) throw refusal;

		const id = crypto.randomBytes(16).toString('hex');
		const secretHash = secret ? sha256Hex(secret) : undefined;
		const entry: WebhookEntry = {
			id,
			url,
			events,
			secret,
			secretHash,
			createdAt: Date.now()
		};
		this.webhooks.set(id, entry);

		// Persist to storage
		if (this.storage) {
			try {
				this.storage.saveWebhook(id, url, events, secretHash, entry.createdAt);
				if (secret) this.saveSecrets();
			} catch {
				// Best-effort — webhook still works in-memory
			}
		}

		return this.toRegistration(entry);
	}

	/**
	 * Unregister a webhook by ID.
	 * @returns true if the webhook was found and removed
	 */
	unregister(id: string): boolean {
		const secret = this.webhooks.get(id)?.secret;
		const deleted = this.webhooks.delete(id);
		this.holdDeliveries.delete(id);
		if (deleted && this.storage) {
			try {
				this.storage.deleteWebhook(id);
				if (secret) this.saveSecrets();
			} catch {
				// Best-effort
			}
		}
		return deleted;
	}

	/**
	 * List all registered webhooks.
	 */
	list(): WebhookRegistration[] {
		return [...this.webhooks.values()].map((w) => this.toRegistration(w));
	}

	/**
	 * Dispatch an event to all matching webhooks.
	 * Fire-and-forget with 1 retry after 2s delay.
	 * Hold lifecycle deliveries, including retries, run in order per webhook
	 * registration and payment hash.
	 */
	dispatch(eventType: string, data: unknown): void {
		let payload: string;
		try {
			// Snapshot once so queued deliveries and retries preserve the event identity.
			payload = JSON.stringify({
				event: eventType,
				data: withoutPreimage(data),
				timestamp: Date.now()
			});
		} catch {
			return;
		}
		const paymentHash = this.holdPaymentHash(eventType, data);

		for (const webhook of this.webhooks.values()) {
			if (webhook.events.includes(eventType) || webhook.events.includes('*')) {
				const deliver = (): Promise<void> =>
					this.deliverWithRetry(webhook, eventType, payload);
				if (paymentHash === undefined) {
					void deliver();
					continue;
				}

				let deliveries = this.holdDeliveries.get(webhook.id);
				if (!deliveries) {
					deliveries = new Map();
					this.holdDeliveries.set(webhook.id, deliveries);
				}
				const previous = deliveries.get(paymentHash);
				const delivery = previous ? previous.then(deliver) : deliver();
				deliveries.set(paymentHash, delivery);
				const queue = deliveries;
				void delivery.then(() => {
					if (queue.get(paymentHash) === delivery) {
						queue.delete(paymentHash);
						if (
							queue.size === 0 &&
							this.holdDeliveries.get(webhook.id) === queue
						) {
							this.holdDeliveries.delete(webhook.id);
						}
					}
				});
			}
		}
	}

	/**
	 * Get the count of registered webhooks.
	 */
	get size(): number {
		return this.webhooks.size;
	}

	/**
	 * Clear all registrations.
	 */
	clear(): void {
		this.webhooks.clear();
		this.holdDeliveries.clear();
		if (this.storage) {
			try {
				this.storage.deleteAllWebhooks();
				this.saveSecrets();
			} catch {
				// Best-effort
			}
		}
	}

	/** Unreadable secrets cost the signatures, not the registrations. */
	private loadSecrets(): Record<string, unknown> {
		try {
			const secrets = this.storage?.loadWebhookSecrets?.();
			return typeof secrets === 'object' && secrets !== null ? secrets : {};
		} catch {
			return {};
		}
	}

	private saveSecrets(): void {
		const secrets: Record<string, string> = {};
		for (const webhook of this.webhooks.values()) {
			if (webhook.secret) secrets[webhook.id] = webhook.secret;
		}
		this.storage?.saveWebhookSecrets?.(secrets);
	}

	private holdPaymentHash(
		eventType: string,
		data: unknown
	): string | undefined {
		if (
			['hold:accepted', 'hold:settled', 'hold:cancelled'].includes(eventType) &&
			typeof data === 'object' &&
			data !== null &&
			'paymentHash' in data &&
			typeof data.paymentHash === 'string'
		) {
			return data.paymentHash;
		}
		return undefined;
	}

	private async deliverWithRetry(
		webhook: WebhookEntry,
		eventType: string,
		payload: string
	): Promise<void> {
		for (let attempt = 0; attempt < 2; attempt++) {
			if (this.webhooks.get(webhook.id) !== webhook) return;
			try {
				await this.deliver(webhook, eventType, payload);
				return;
			} catch {
				if (attempt === 0 && this.webhooks.get(webhook.id) === webhook) {
					await new Promise((resolve) => setTimeout(resolve, RETRY_DELAY_MS));
				}
				// Silently drop after the retry so the next queued event can proceed.
			}
		}
	}

	private async deliver(
		webhook: WebhookEntry,
		eventType: string,
		payload: string
	): Promise<void> {
		const url = new URL(webhook.url);
		// A row stored before register() checked the scheme.
		if (url.protocol !== 'http:' && url.protocol !== 'https:') {
			throw new Error(`Webhook url scheme ${url.protocol} is not delivered`);
		}
		const isHttps = url.protocol === 'https:';
		const lib = isHttps ? https : http;

		const headers: Record<string, string> = {
			'Content-Type': 'application/json',
			'Content-Length': Buffer.byteLength(payload).toString(),
			'User-Agent': 'Beignet-Webhook/1.0',
			'X-Webhook-Event': eventType
		};

		// HMAC-SHA256 signature if secret is configured
		if (webhook.secret) {
			const sig = crypto
				.createHmac('sha256', webhook.secret)
				.update(payload)
				.digest('hex');
			headers['X-Webhook-Signature'] = `sha256=${sig}`;
		}

		return new Promise((resolve, reject) => {
			const req = lib.request(
				{
					hostname: url.hostname,
					port: url.port || (isHttps ? 443 : 80),
					path: url.pathname + url.search,
					method: 'POST',
					headers,
					timeout: DELIVERY_TIMEOUT_MS
				},
				(res) => {
					// Consume response body to free memory
					res.resume();
					if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
						resolve();
					} else {
						reject(
							new Error(`Webhook delivery failed: HTTP ${res.statusCode}`)
						);
					}
				}
			);

			req.on('timeout', () => {
				req.destroy();
				reject(new Error('Webhook delivery timed out'));
			});

			req.on('error', (err) => {
				reject(err);
			});

			req.write(payload);
			req.end();
		});
	}

	private toRegistration(entry: WebhookEntry): WebhookRegistration {
		const reg: WebhookRegistration = {
			id: entry.id,
			url: entry.url,
			events: entry.events,
			createdAt: entry.createdAt
		};
		// Don't expose secret in list responses
		if (entry.secret || entry.secretHash) {
			reg.secret = '***';
		}
		return reg;
	}
}
