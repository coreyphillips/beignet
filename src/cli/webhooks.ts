/**
 * WebhookManager: Manages webhook registrations and dispatches events.
 * Supports optional persistent storage — when storage is provided, webhooks
 * survive daemon restarts. Without storage, falls back to ephemeral (in-memory).
 * HMAC-SHA256 signing via optional secret for payload verification.
 */

import * as http from 'http';
import * as https from 'https';
import * as crypto from 'crypto';

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
}

interface WebhookEntry extends WebhookRegistration {
	// internal: secretHash for storage (not the raw secret)
	secretHash?: string;
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
				for (const row of this.storage.loadAllWebhooks()) {
					this.webhooks.set(row.id, {
						id: row.id,
						url: row.url,
						events: row.events,
						secretHash: row.secretHash,
						createdAt: row.createdAt
						// Note: raw secret is NOT recoverable from hash — webhook
						// signature verification won't work after restart. The agent
						// should re-register with a secret if HMAC is needed.
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

		const id = crypto.randomBytes(16).toString('hex');
		const secretHash = secret
			? crypto.createHash('sha256').update(secret).digest('hex')
			: undefined;
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
		const deleted = this.webhooks.delete(id);
		this.holdDeliveries.delete(id);
		if (deleted && this.storage) {
			try {
				this.storage.deleteWebhook(id);
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
				data,
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
			} catch {
				// Best-effort
			}
		}
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
