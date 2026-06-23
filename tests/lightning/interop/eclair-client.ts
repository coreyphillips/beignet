/**
 * Eclair REST API Client for interop testing.
 *
 * Zero-dependency client using Node.js built-in http module.
 * Communicates with Eclair via HTTP Basic Auth.
 * All requests are POST with application/x-www-form-urlencoded bodies.
 */

import http from 'http';

// ── Types ──────────────────────────────────────────────────────

export interface IEclairInfo {
	version: string;
	nodeId: string;
	alias: string;
	color: string;
	publicAddresses: string[];
	blockHeight: number;
	network: string;
}

export interface IEclairPeer {
	nodeId: string;
	state: string;
	address?: string;
}

export interface IEclairChannel {
	nodeId: string;
	channelId: string;
	state: string;
	data?: {
		commitments?: {
			active?: Array<{
				localCommit?: {
					spec?: {
						toLocal?: number;
						toRemote?: number;
					};
				};
			}>;
		};
	};
}

export interface IEclairInvoice {
	prefix: string;
	timestamp: number;
	nodeId: string;
	serialized: string;
	description: string;
	paymentHash: string;
	paymentMetadata?: string;
	amount?: number;
}

export interface IEclairSentInfo {
	id: string;
	parentId: string;
	paymentHash: string;
	paymentType: string;
	amount: number;
	recipientAmount: number;
	recipientNodeId: string;
	status: {
		type: string;
		paymentPreimage?: string;
		failedNode?: string;
		failureMessage?: string;
	};
}

export interface IEclairReceivedInfo {
	paymentRequest: {
		paymentHash: string;
		amount: number;
	};
	paymentType: string;
	status: {
		type: string;
		amount?: number;
		receivedAt?: number;
	};
}

// ── Client ─────────────────────────────────────────────────────

export class EclairRestClient {
	private host: string;
	private port: number;
	private authHeader: string;

	constructor(host: string, port: number, password: string) {
		this.host = host;
		this.port = port;
		// Eclair uses Basic Auth with empty username
		this.authHeader = 'Basic ' + Buffer.from(`:${password}`).toString('base64');
	}

	private async request<T>(
		path: string,
		params?: Record<string, string>
	): Promise<T> {
		return new Promise((resolve, reject) => {
			const bodyStr = params
				? Object.entries(params)
						.map(
							([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`
						)
						.join('&')
				: '';

			const options: http.RequestOptions = {
				hostname: this.host,
				port: this.port,
				path,
				method: 'POST',
				headers: {
					Authorization: this.authHeader,
					'Content-Type': 'application/x-www-form-urlencoded',
					'Content-Length': Buffer.byteLength(bodyStr)
				}
			};

			const req = http.request(options, (res) => {
				let data = '';
				res.on('data', (chunk) => {
					data += chunk;
				});
				res.on('end', () => {
					try {
						const parsed = JSON.parse(data);
						if (res.statusCode && res.statusCode >= 400) {
							reject(
								new Error(
									`Eclair API error ${res.statusCode}: ${
										typeof parsed === 'string'
											? parsed
											: parsed.error || JSON.stringify(parsed)
									}`
								)
							);
						} else {
							resolve(parsed as T);
						}
					} catch {
						// Some Eclair endpoints return plain strings
						if (res.statusCode && res.statusCode >= 400) {
							reject(new Error(`Eclair API error ${res.statusCode}: ${data}`));
						} else {
							resolve(data as unknown as T);
						}
					}
				});
			});

			req.on('error', reject);

			if (bodyStr) {
				req.write(bodyStr);
			}
			req.end();
		});
	}

	// ── Info ──

	async getInfo(): Promise<IEclairInfo> {
		return this.request('/getinfo');
	}

	// ── Peers ──

	async connect(nodeId: string, host: string, port: number): Promise<string> {
		return this.request('/connect', {
			uri: `${nodeId}@${host}:${port}`
		});
	}

	async peers(): Promise<IEclairPeer[]> {
		return this.request('/peers');
	}

	async disconnect(nodeId: string): Promise<string> {
		return this.request('/disconnect', { nodeId });
	}

	// ── Channels ──

	async open(
		nodeId: string,
		fundingSatoshis: number,
		pushMsat?: number,
		channelType = 'anchor_outputs_zero_fee_htlc_tx',
		fundingFeeBudgetSatoshis = 100_000
	): Promise<string> {
		const params: Record<string, string> = {
			nodeId,
			fundingSatoshis: String(fundingSatoshis),
			channelType,
			fundingFeeBudgetSatoshis: String(fundingFeeBudgetSatoshis)
		};
		if (pushMsat !== undefined) {
			params.pushMsat = String(pushMsat);
		}
		return this.request('/open', params);
	}

	async channels(nodeId?: string): Promise<IEclairChannel[]> {
		const params = nodeId ? { nodeId } : undefined;
		return this.request('/channels', params);
	}

	async close(channelId: string): Promise<string> {
		return this.request('/close', { channelId });
	}

	async forceClose(channelId: string): Promise<string> {
		return this.request('/forceclose', { channelId });
	}

	// ── Invoices ──

	async createInvoice(
		amountMsat: number,
		description: string
	): Promise<IEclairInvoice> {
		return this.request('/createinvoice', {
			amountMsat: String(amountMsat),
			description
		});
	}

	async getInvoice(paymentHash: string): Promise<IEclairReceivedInfo> {
		return this.request('/getreceivedinfo', { paymentHash });
	}

	// ── Payments ──

	async payInvoice(invoice: string): Promise<string> {
		return this.request('/payinvoice', { invoice });
	}

	async getSentInfo(paymentHash: string): Promise<IEclairSentInfo[]> {
		return this.request('/getsentinfo', { paymentHash });
	}

	// ── Wallet ──

	async getNewAddress(): Promise<string> {
		return this.request('/getnewaddress');
	}
}
