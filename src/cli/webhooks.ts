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
	 */
	dispatch(eventType: string, data: unknown): void {
		for (const webhook of this.webhooks.values()) {
			if (webhook.events.includes(eventType) || webhook.events.includes('*')) {
				this.deliver(webhook, eventType, data).catch(() => {
					// Retry once after delay
					setTimeout(() => {
						this.deliver(webhook, eventType, data).catch(() => {
							// Silently drop after retry
						});
					}, RETRY_DELAY_MS);
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
		if (this.storage) {
			try {
				this.storage.deleteAllWebhooks();
			} catch {
				// Best-effort
			}
		}
	}

	private async deliver(
		webhook: WebhookEntry,
		eventType: string,
		data: unknown
	): Promise<void> {
		const payload = JSON.stringify({
			event: eventType,
			data,
			timestamp: Date.now()
		});
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
