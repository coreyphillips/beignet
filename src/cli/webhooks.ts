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

export { WEBHOOK_SECRETS_STORAGE_KEY } from './daemon-state-keys';

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

/**
 * Ceilings on the delivery work a WebhookManager holds at once. An event that
 * would take a registration, or all of them, past its byte ceiling is dropped
 * for that registration and counted as an overflow.
 */
export interface WebhookDeliveryOptions {
	/** Deliveries in flight or waiting to retry, across registrations (default 32) */
	maxActiveDeliveries?: number;
	/** Deliveries in flight or waiting to retry, per registration (default 4) */
	maxActivePerWebhook?: number;
	/**
	 * Payload bytes held by queued and active deliveries, across registrations
	 * (default 8 MiB). An event matching several registrations counts once
	 * for each.
	 */
	maxQueuedBytes?: number;
	/** Payload bytes held by queued and active deliveries, per registration (default 1 MiB) */
	maxQueuedBytesPerWebhook?: number;
	/** Longest one attempt may take, response body included (default 5000) */
	timeoutMs?: number;
	/** Pause before the one retry of a failed attempt (default 2000) */
	retryDelayMs?: number;
}

/** What a WebhookManager holds now, and what its deliveries came to. */
export interface WebhookDeliveryStats {
	/** Deliveries in flight or waiting to retry */
	active: number;
	/** Deliveries waiting for a free worker */
	queued: number;
	/** Payload bytes held by queued and active deliveries */
	queuedBytes: number;
	/** Deliveries a recipient answered with 2xx */
	delivered: number;
	/** Deliveries dropped after both attempts failed */
	failed: number;
	/** Deliveries refused at dispatch because a byte ceiling was reached */
	overflowed: number;
	/** Deliveries dropped because their registration was removed or the manager stopped */
	discarded: number;
}

/** Prometheus text lines for a manager's delivery stats. */
export function webhookMetrics(stats: WebhookDeliveryStats): string {
	const outcomes: Array<[string, number]> = [
		['delivered', stats.delivered],
		['failed', stats.failed],
		['overflow', stats.overflowed],
		['discarded', stats.discarded]
	];
	return (
		[
			'# HELP beignet_webhook_deliveries_active Webhook deliveries in flight or waiting to retry',
			'# TYPE beignet_webhook_deliveries_active gauge',
			`beignet_webhook_deliveries_active ${stats.active}`,
			'# HELP beignet_webhook_deliveries_queued Webhook deliveries waiting for a worker',
			'# TYPE beignet_webhook_deliveries_queued gauge',
			`beignet_webhook_deliveries_queued ${stats.queued}`,
			'# HELP beignet_webhook_queued_bytes Payload bytes held by queued and active webhook deliveries',
			'# TYPE beignet_webhook_queued_bytes gauge',
			`beignet_webhook_queued_bytes ${stats.queuedBytes}`,
			'# HELP beignet_webhook_deliveries_total Webhook deliveries by outcome',
			'# TYPE beignet_webhook_deliveries_total counter',
			...outcomes.map(
				([outcome, count]) =>
					`beignet_webhook_deliveries_total{outcome="${outcome}"} ${count}`
			)
		].join('\n') + '\n'
	);
}

interface WebhookEntry extends WebhookRegistration {
	// internal: secretHash for storage (not the raw secret)
	secretHash?: string;
}

interface QueuedDelivery {
	eventType: string;
	payload: string;
	bytes: number;
	paymentHash?: string;
}

/** One registration's share of the delivery work. */
interface Destination {
	webhook: WebhookEntry;
	ready: QueuedDelivery[];
	// Hold deliveries waiting behind an earlier one for the same payment hash.
	// A hash is a key while that earlier delivery is in `ready` or running.
	lanes: Map<string, QueuedDelivery[]>;
	active: number;
	bytes: number;
	inLine: boolean;
	removed: boolean;
}

interface RunningDelivery {
	destination: Destination;
	request?: http.ClientRequest;
	endPause?: () => void;
}

type DeliveryOutcome = 'delivered' | 'failed' | 'discarded';

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

const DEFAULT_MAX_ACTIVE_DELIVERIES = 32;
const DEFAULT_MAX_ACTIVE_PER_WEBHOOK = 4;
const DEFAULT_MAX_QUEUED_BYTES = 8 * 1024 * 1024;
const DEFAULT_MAX_QUEUED_BYTES_PER_WEBHOOK = 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 5000;
const DEFAULT_RETRY_DELAY_MS = 2000;

export class WebhookManager {
	private webhooks: Map<string, WebhookEntry> = new Map();
	private storage: IWebhookStorage | null;
	private maxActiveDeliveries: number;
	private maxActivePerWebhook: number;
	private maxQueuedBytes: number;
	private maxQueuedBytesPerWebhook: number;
	private timeoutMs: number;
	private retryDelayMs: number;
	private destinations = new Map<string, Destination>();
	// Destinations with a ready delivery and a free worker of their own. Each
	// turn starts one delivery, so a backlog at one cannot starve the rest.
	private line: Destination[] = [];
	private running = new Set<RunningDelivery>();
	private queued = 0;
	private queuedBytes = 0;
	private outcomes = { delivered: 0, failed: 0, overflowed: 0, discarded: 0 };
	private stopped = false;
	private idleWaiters: Array<() => void> = [];

	constructor(storage?: IWebhookStorage, options?: WebhookDeliveryOptions) {
		this.storage = storage ?? null;
		this.maxActiveDeliveries = Math.max(
			1,
			options?.maxActiveDeliveries ?? DEFAULT_MAX_ACTIVE_DELIVERIES
		);
		this.maxActivePerWebhook = Math.max(
			1,
			options?.maxActivePerWebhook ?? DEFAULT_MAX_ACTIVE_PER_WEBHOOK
		);
		this.maxQueuedBytes = Math.max(
			1,
			options?.maxQueuedBytes ?? DEFAULT_MAX_QUEUED_BYTES
		);
		this.maxQueuedBytesPerWebhook = Math.max(
			1,
			options?.maxQueuedBytesPerWebhook ?? DEFAULT_MAX_QUEUED_BYTES_PER_WEBHOOK
		);
		this.timeoutMs = Math.max(1, options?.timeoutMs ?? DEFAULT_TIMEOUT_MS);
		this.retryDelayMs = Math.max(
			0,
			options?.retryDelayMs ?? DEFAULT_RETRY_DELAY_MS
		);

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
		const destination = this.destinations.get(id);
		if (destination) this.discard(destination);
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
	 * Best effort, with 1 retry after a failed attempt. Deliveries wait for a
	 * worker within the configured ceilings; one that would pass a byte
	 * ceiling is dropped and counted in deliveryStats().overflowed.
	 * Hold lifecycle deliveries, including retries, run in order per webhook
	 * registration and payment hash.
	 */
	dispatch(eventType: string, data: unknown): void {
		if (this.stopped) return;
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
		const bytes = Buffer.byteLength(payload);
		const paymentHash = this.holdPaymentHash(eventType, data);

		for (const webhook of this.webhooks.values()) {
			if (
				!webhook.events.includes(eventType) &&
				!webhook.events.includes('*')
			) {
				continue;
			}
			let destination = this.destinations.get(webhook.id);
			if (
				(destination?.bytes ?? 0) + bytes > this.maxQueuedBytesPerWebhook ||
				this.queuedBytes + bytes > this.maxQueuedBytes
			) {
				this.outcomes.overflowed++;
				continue;
			}
			if (!destination) {
				destination = {
					webhook,
					ready: [],
					lanes: new Map(),
					active: 0,
					bytes: 0,
					inLine: false,
					removed: false
				};
				this.destinations.set(webhook.id, destination);
			}
			destination.bytes += bytes;
			this.queuedBytes += bytes;
			this.queued++;
			this.enqueue(destination, { eventType, payload, bytes, paymentHash });
		}
		this.pump();
	}

	/** Work held now, and running totals of how deliveries ended. */
	deliveryStats(): WebhookDeliveryStats {
		return {
			active: this.running.size,
			queued: this.queued,
			queuedBytes: this.queuedBytes,
			...this.outcomes
		};
	}

	/**
	 * Stop delivering, for good: queued deliveries are dropped, retry pauses
	 * end, requests in flight are aborted and later dispatches are ignored.
	 * Registrations are kept. Resolves once no delivery is running.
	 */
	stop(): Promise<void> {
		this.stopped = true;
		for (const destination of [...this.destinations.values()]) {
			this.discard(destination);
		}
		for (const run of this.running) run.request?.destroy();
		if (this.running.size === 0) return Promise.resolve();
		return new Promise((resolve) => this.idleWaiters.push(resolve));
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
		for (const destination of [...this.destinations.values()]) {
			this.discard(destination);
		}
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

	private enqueue(destination: Destination, delivery: QueuedDelivery): void {
		const hash = delivery.paymentHash;
		if (hash !== undefined) {
			const lane = destination.lanes.get(hash);
			if (lane) {
				lane.push(delivery);
				return;
			}
			destination.lanes.set(hash, []);
		}
		destination.ready.push(delivery);
		this.joinLine(destination);
	}

	private joinLine(destination: Destination): void {
		if (
			destination.inLine ||
			destination.removed ||
			destination.ready.length === 0 ||
			destination.active >= this.maxActivePerWebhook
		) {
			return;
		}
		destination.inLine = true;
		this.line.push(destination);
	}

	private pump(): void {
		while (
			this.running.size < this.maxActiveDeliveries &&
			this.line.length > 0
		) {
			const destination = this.line.shift()!;
			destination.inLine = false;
			const delivery = destination.ready.shift();
			if (destination.removed || !delivery) continue;
			this.start(destination, delivery);
			this.joinLine(destination);
		}
	}

	private start(destination: Destination, delivery: QueuedDelivery): void {
		const run: RunningDelivery = { destination };
		this.running.add(run);
		destination.active++;
		this.queued--;
		void this.deliverWithRetry(run, delivery).then((outcome) => {
			this.outcomes[outcome]++;
			this.running.delete(run);
			destination.active--;
			destination.bytes -= delivery.bytes;
			this.queuedBytes -= delivery.bytes;
			if (delivery.paymentHash !== undefined && !destination.removed) {
				const lane = destination.lanes.get(delivery.paymentHash);
				const next = lane?.shift();
				if (next) destination.ready.push(next);
				else destination.lanes.delete(delivery.paymentHash);
			}
			if (
				destination.active === 0 &&
				destination.ready.length === 0 &&
				this.destinations.get(destination.webhook.id) === destination
			) {
				this.destinations.delete(destination.webhook.id);
			}
			this.joinLine(destination);
			this.pump();
			if (this.running.size === 0) {
				const waiters = this.idleWaiters;
				this.idleWaiters = [];
				for (const resolve of waiters) resolve();
			}
		});
	}

	/**
	 * Drop a registration's queued deliveries and end its retry pauses. Its
	 * requests in flight finish on their own and keep their bytes until then.
	 */
	private discard(destination: Destination): void {
		destination.removed = true;
		if (this.destinations.get(destination.webhook.id) === destination) {
			this.destinations.delete(destination.webhook.id);
		}
		const dropped = [
			...destination.ready,
			...[...destination.lanes.values()].flat()
		];
		destination.ready = [];
		destination.lanes.clear();
		for (const delivery of dropped) {
			destination.bytes -= delivery.bytes;
			this.queuedBytes -= delivery.bytes;
		}
		this.queued -= dropped.length;
		this.outcomes.discarded += dropped.length;
		for (const run of this.running) {
			if (run.destination === destination) run.endPause?.();
		}
	}

	private isCurrent(destination: Destination): boolean {
		return (
			!destination.removed &&
			this.webhooks.get(destination.webhook.id) === destination.webhook
		);
	}

	/** Never rejects: the outcome is all its caller needs. */
	private async deliverWithRetry(
		run: RunningDelivery,
		delivery: QueuedDelivery
	): Promise<DeliveryOutcome> {
		for (let attempt = 0; ; attempt++) {
			if (!this.isCurrent(run.destination)) return 'discarded';
			try {
				await this.deliver(run, delivery);
				return 'delivered';
			} catch {
				if (!this.isCurrent(run.destination)) return 'discarded';
				// Drop after the retry so the next queued event can proceed.
				if (attempt === 1) return 'failed';
				await this.pause(run);
			}
		}
	}

	private pause(run: RunningDelivery): Promise<void> {
		return new Promise((resolve) => {
			const timer = setTimeout(() => run.endPause?.(), this.retryDelayMs);
			run.endPause = (): void => {
				clearTimeout(timer);
				run.endPause = undefined;
				resolve();
			};
		});
	}

	private async deliver(
		run: RunningDelivery,
		{ eventType, payload }: QueuedDelivery
	): Promise<void> {
		const webhook = run.destination.webhook;
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

		// Settled on the request's close, which comes after the response body
		// ends, so the socket stays counted against the worker limits until it
		// is released. The deadline covers a recipient that trickles its reply.
		return new Promise((resolve, reject) => {
			let status: number | undefined;
			let failure: Error | undefined;
			const req = lib.request(
				{
					hostname: url.hostname,
					port: url.port || (isHttps ? 443 : 80),
					path: url.pathname + url.search,
					method: 'POST',
					headers
				},
				(res) => {
					status = res.statusCode;
					// A response cut off mid-body emits an error of its own.
					res.on('error', () => undefined);
					// Consume response body to free memory
					res.resume();
				}
			);
			const deadline = setTimeout(
				() => req.destroy(new Error('Webhook delivery timed out')),
				this.timeoutMs
			);
			run.request = req;

			req.on('error', (err) => {
				failure ??= err;
			});

			req.on('close', () => {
				clearTimeout(deadline);
				run.request = undefined;
				if (status !== undefined && status >= 200 && status < 300) {
					resolve();
				} else {
					reject(
						failure ?? new Error(`Webhook delivery failed: HTTP ${status}`)
					);
				}
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
