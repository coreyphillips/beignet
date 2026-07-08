/**
 * LND REST API Client for interop testing.
 *
 * Zero-dependency client using Node.js built-in https module.
 * Communicates with LND via REST API with macaroon authentication.
 */

import https from 'https';

// ── Types ──────────────────────────────────────────────────────

export interface ILndInfo {
	identity_pubkey: string;
	alias: string;
	num_active_channels: number;
	num_peers: number;
	block_height: number;
	synced_to_chain: boolean;
	version: string;
}

export interface ILndPeer {
	pub_key: string;
	address: string;
	bytes_sent: string;
	bytes_recv: string;
	inbound: boolean;
}

export interface ILndChannel {
	active: boolean;
	remote_pubkey: string;
	channel_point: string;
	chan_id: string;
	capacity: string;
	local_balance: string;
	remote_balance: string;
}

export interface ILndPendingChannels {
	pending_open_channels: Array<{
		channel: {
			remote_node_pub: string;
			channel_point: string;
			capacity: string;
			local_balance: string;
			remote_balance: string;
		};
	}>;
	pending_force_closing_channels?: Array<{
		channel?: {
			remote_node_pub: string;
			channel_point: string;
		};
	}>;
}

export interface ILndInvoice {
	r_hash: string;
	payment_request: string;
	settled: boolean;
	value: string;
	state: string;
	amt_paid_sat?: string;
	amt_paid_msat?: string;
}

export interface ILndPaymentResponse {
	payment_error: string;
	payment_preimage: string;
	payment_route: {
		total_amt: string;
		total_fees: string;
	};
}

export interface ILndWalletBalance {
	total_balance: string;
	confirmed_balance: string;
	unconfirmed_balance: string;
}

export interface ILndNewAddress {
	address: string;
}

export interface ILndOpenChannelResponse {
	funding_txid_bytes: string;
	funding_txid_str: string;
	output_index: number;
}

export interface ILndCloseChannelResponse {
	closing_txid: string;
}

// ── Client ─────────────────────────────────────────────────────

export class LndRestClient {
	private host: string;
	private port: number;
	private macaroonHex: string;

	constructor(host: string, port: number, macaroonHex: string) {
		this.host = host;
		this.port = port;
		this.macaroonHex = macaroonHex;
	}

	private async request<T>(
		method: string,
		path: string,
		body?: Record<string, unknown>
	): Promise<T> {
		return new Promise((resolve, reject) => {
			const options: https.RequestOptions = {
				hostname: this.host,
				port: this.port,
				path,
				method,
				headers: {
					'Grpc-Metadata-macaroon': this.macaroonHex,
					'Content-Type': 'application/json'
				},
				rejectUnauthorized: false
			};

			const req = https.request(options, (res) => {
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
									`LND API error ${res.statusCode}: ${
										parsed.message || parsed.error || data
									}`
								)
							);
						} else {
							resolve(parsed as T);
						}
					} catch {
						reject(new Error(`Failed to parse LND response: ${data}`));
					}
				});
			});

			req.on('error', reject);

			if (body) {
				req.write(JSON.stringify(body));
			}
			req.end();
		});
	}

	// ── Info ──

	async getInfo(): Promise<ILndInfo> {
		return this.request('GET', '/v1/getinfo');
	}

	// ── Peers ──

	async connectPeer(pubkey: string, host: string): Promise<void> {
		await this.request('POST', '/v1/peers', {
			addr: { pubkey, host },
			perm: false
		});
	}

	async listPeers(): Promise<{ peers: ILndPeer[] }> {
		return this.request('GET', '/v1/peers');
	}

	async disconnectPeer(pubkey: string): Promise<void> {
		await this.request('DELETE', `/v1/peers/${pubkey}`);
	}

	// ── Channels ──

	async openChannelSync(
		nodePubkey: string,
		localFundingAmount: number,
		pushSat = 0
	): Promise<ILndOpenChannelResponse> {
		return this.request('POST', '/v1/channels', {
			node_pubkey_string: nodePubkey,
			local_funding_amount: String(localFundingAmount),
			push_sat: String(pushSat),
			spend_unconfirmed: true
		});
	}

	/**
	 * Open a zero-conf channel.
	 * Requires --protocol.zero-conf and --protocol.option-scid-alias on LND.
	 */
	async openZeroConfChannelSync(
		nodePubkey: string,
		localFundingAmount: number,
		pushSat = 0
	): Promise<ILndOpenChannelResponse> {
		return this.request('POST', '/v1/channels', {
			node_pubkey_string: nodePubkey,
			local_funding_amount: String(localFundingAmount),
			push_sat: String(pushSat),
			spend_unconfirmed: true,
			zero_conf: true,
			scid_alias: true,
			commitment_type: 'ANCHORS'
		});
	}

	async listChannels(): Promise<{ channels: ILndChannel[] }> {
		return this.request('GET', '/v1/channels');
	}

	async pendingChannels(): Promise<ILndPendingChannels> {
		return this.request('GET', '/v1/channels/pending');
	}

	/**
	 * Cooperative close a channel (fire-and-forget — the response is a stream).
	 * LND returns a streaming (chunked) response for close updates.
	 * We resolve as soon as the first data chunk arrives and destroy the socket.
	 */
	async closeChannel(fundingTxid: string, outputIndex: number): Promise<void> {
		return new Promise((resolve, reject) => {
			const options: https.RequestOptions = {
				hostname: this.host,
				port: this.port,
				path: `/v1/channels/${fundingTxid}/${outputIndex}`,
				method: 'DELETE',
				headers: {
					'Grpc-Metadata-macaroon': this.macaroonHex,
					'Content-Type': 'application/json'
				},
				rejectUnauthorized: false
			};

			const req = https.request(options, (res) => {
				res.once('data', () => {
					// First chunk received means close was initiated
					res.destroy();
					resolve();
				});
				res.on('error', () => {
					// Socket destroyed — expected
					resolve();
				});
			});

			req.on('error', (err) => {
				reject(err);
			});

			// Timeout: if no response in 30s, assume close was initiated
			req.setTimeout(30_000, () => {
				req.destroy();
				resolve();
			});

			req.end();
		});
	}

	/**
	 * Force close a channel (fire-and-forget — the response is a stream).
	 * LND returns a streaming (chunked) response that never ends, so we
	 * resolve as soon as the first data chunk arrives and destroy the socket.
	 */
	async forceCloseChannel(
		fundingTxid: string,
		outputIndex: number
	): Promise<void> {
		return new Promise((resolve, reject) => {
			const options: https.RequestOptions = {
				hostname: this.host,
				port: this.port,
				path: `/v1/channels/${fundingTxid}/${outputIndex}?force=true`,
				method: 'DELETE',
				headers: {
					'Grpc-Metadata-macaroon': this.macaroonHex,
					'Content-Type': 'application/json'
				},
				rejectUnauthorized: false
			};

			const req = https.request(options, (res) => {
				res.once('data', () => {
					// First chunk received means force close was initiated
					res.destroy();
					resolve();
				});
				res.on('error', () => {
					// Socket destroyed — expected
					resolve();
				});
			});

			req.on('error', (err) => {
				// Connection-level errors
				reject(err);
			});

			// Timeout: if no response in 15s, assume force close was sent
			req.setTimeout(15_000, () => {
				req.destroy();
				resolve();
			});

			req.end();
		});
	}

	async closedChannels(): Promise<{
		channels: Array<{
			channel_point: string;
			closing_tx_hash: string;
			close_type: string;
		}>;
	}> {
		return this.request('GET', '/v1/channels/closed');
	}

	/**
	 * Update the forwarding policy of one channel. Side effect used by tests:
	 * LND signs and sends a FRESH channel_update to the channel peer (also for
	 * private channels, directly over the connection).
	 */
	async updateChannelPolicy(
		fundingTxid: string,
		outputIndex: number,
		policy: {
			baseFeeMsat: string;
			feeRatePpm: number;
			timeLockDelta: number;
		}
	): Promise<unknown> {
		return this.request('POST', '/v1/chanpolicy', {
			chan_point: {
				funding_txid_str: fundingTxid,
				output_index: outputIndex
			},
			base_fee_msat: policy.baseFeeMsat,
			fee_rate_ppm: policy.feeRatePpm,
			time_lock_delta: policy.timeLockDelta
		});
	}

	// ── Invoices ──

	async addInvoice(valueSat: number, memo?: string): Promise<ILndInvoice> {
		return this.request('POST', '/v1/invoices', {
			value: String(valueSat),
			memo: memo || ''
		});
	}

	async lookupInvoice(rHashHex: string): Promise<ILndInvoice> {
		return this.request('GET', `/v1/invoice/${rHashHex}`);
	}

	/**
	 * Create a hold (hodl) invoice for a payment hash we control. LND accepts the
	 * incoming HTLC but holds it (state ACCEPTED) without settling, so the payer's
	 * offered HTLC stays committed and unresolved — exactly what we need to
	 * force-close with a pending HTLC. Requires LND's invoicesrpc.
	 */
	async addHoldInvoice(
		paymentHashHex: string,
		valueSat: number
	): Promise<{ payment_request: string }> {
		return this.request('POST', '/v2/invoices/hodl', {
			hash: Buffer.from(paymentHashHex, 'hex').toString('base64'),
			value: String(valueSat)
		});
	}

	/** Cancel a hold invoice (cleanup so LND fails the HTLC back). */
	async cancelHoldInvoice(paymentHashHex: string): Promise<void> {
		await this.request('POST', '/v2/invoices/cancel', {
			payment_hash: Buffer.from(paymentHashHex, 'hex').toString('base64')
		});
	}

	// ── Payments ──

	async sendPaymentSync(payReq: string): Promise<ILndPaymentResponse> {
		return this.request('POST', '/v1/channels/transactions', {
			payment_request: payReq
		});
	}

	// ── Wallet ──

	async walletBalance(): Promise<ILndWalletBalance> {
		return this.request('GET', '/v1/balance/blockchain');
	}

	async newAddress(type = 'WITNESS_PUBKEY_HASH'): Promise<ILndNewAddress> {
		return this.request('GET', `/v1/newaddress?type=${type}`);
	}
}
