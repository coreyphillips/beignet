/**
 * CLN (Core Lightning) REST API Client for interop testing.
 *
 * Zero-dependency client using Node.js built-in https module.
 * Communicates with CLN via CLNRest API (HTTPS) with rune authentication.
 */

import https from 'https';

// ── Types ──────────────────────────────────────────────────────

export interface IClnInfo {
	id: string;
	alias: string;
	blockheight: number;
	network: string;
	version: string;
	num_peers: number;
	num_active_channels: number;
}

export interface IClnPeer {
	id: string;
	connected: boolean;
	netaddr: string[];
}

export interface IClnChannel {
	peer_id: string;
	channel_id: string;
	short_channel_id?: string;
	state: string;
	funding_txid?: string;
	funding_outnum?: number;
	to_us_msat?: string | number;
	total_msat?: string | number;
}

export interface IClnFundChannelResponse {
	tx: string;
	txid: string;
	outnum: number;
	channel_id: string;
}

export interface IClnInvoice {
	bolt11: string;
	payment_hash: string;
	payment_secret: string;
	label: string;
	status: string;
	amount_msat?: string | number;
	amount_received_msat?: string | number;
}

export interface IClnPayResponse {
	payment_preimage: string;
	payment_hash: string;
	status: string;
	amount_msat?: string | number;
	amount_sent_msat?: string | number;
}

export interface IClnNewAddr {
	bech32: string;
}

export interface IClnCloseResponse {
	type: string;
	tx: string;
	txid: string;
}

export interface IClnOfferResponse {
	offer_id: string;
	active: boolean;
	single_use: boolean;
	bolt12: string;
	used: boolean;
}

export interface IClnFetchInvoiceResponse {
	invoice: string;
	changes?: Record<string, unknown>;
}

export interface IClnSpliceInitResponse {
	psbt: string;
}

export interface IClnSpliceUpdateResponse {
	psbt: string;
	commitments_secured: boolean;
}

export interface IClnSpliceSignedResponse {
	tx: string;
	txid: string;
}

// ── Helpers ────────────────────────────────────────────────────

/**
 * Parse CLN msat amount strings.
 * CLN returns amounts with suffixes like "500000000msat" or "500000sat".
 */
export function parseClnMsat(val: string | number | undefined): bigint {
	if (val === undefined || val === null) return 0n;
	if (typeof val === 'number') return BigInt(val);
	const s = String(val);
	if (s.endsWith('msat')) return BigInt(s.slice(0, -4));
	if (s.endsWith('sat')) return BigInt(s.slice(0, -3)) * 1000n;
	if (s.endsWith('btc'))
		return BigInt(Math.round(parseFloat(s.slice(0, -3)) * 1e11)) * 1000n;
	return BigInt(s);
}

// ── Client ─────────────────────────────────────────────────────

export class ClnRestClient {
	private host: string;
	private port: number;
	private rune: string;

	constructor(host: string, port: number, rune: string) {
		this.host = host;
		this.port = port;
		this.rune = rune;
	}

	private async request<T>(
		method: string,
		path: string,
		body?: Record<string, unknown>
	): Promise<T> {
		return new Promise((resolve, reject) => {
			const bodyStr = body ? JSON.stringify(body) : undefined;

			const options: https.RequestOptions = {
				hostname: this.host,
				port: this.port,
				path,
				method,
				rejectUnauthorized: false,
				headers: {
					Rune: this.rune,
					'Content-Type': 'application/json',
					Accept: 'application/json'
				}
			};

			if (bodyStr) {
				options.headers!['Content-Length'] = Buffer.byteLength(bodyStr);
			}

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
									`CLN API error ${res.statusCode}: ${
										parsed.message || parsed.error || data
									}`
								)
							);
						} else {
							resolve(parsed as T);
						}
					} catch {
						reject(new Error(`Failed to parse CLN response: ${data}`));
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

	async getInfo(): Promise<IClnInfo> {
		return this.request('POST', '/v1/getinfo');
	}

	// ── Peers ──

	async connectPeer(id: string, host: string, port: number): Promise<void> {
		await this.request('POST', '/v1/connect', {
			id: `${id}@${host}:${port}`
		});
	}

	async listPeers(): Promise<{ peers: IClnPeer[] }> {
		return this.request('POST', '/v1/listpeers');
	}

	async disconnectPeer(id: string): Promise<void> {
		await this.request('POST', '/v1/disconnect', { id });
	}

	// ── Channels ──

	async fundChannel(
		id: string,
		amount: number | string,
		pushMsat?: number
	): Promise<IClnFundChannelResponse> {
		const body: Record<string, unknown> = {
			id,
			amount: String(amount)
		};
		if (pushMsat !== undefined) {
			body.push_msat = pushMsat;
		}
		return this.request('POST', '/v1/fundchannel', body);
	}

	async listChannels(): Promise<{ channels: IClnChannel[] }> {
		return this.request('POST', '/v1/listpeerchannels');
	}

	/**
	 * Buy an inbound-liquidity lease while opening (bLIP-0051): v2 open with
	 * request_amt; compact_lease is the hex lease_rates we expect the seller
	 * to sign (CLN aborts if the peer's will_fund rates differ).
	 */
	async fundChannelLease(
		id: string,
		amount: number,
		requestAmt: number,
		compactLease: string
	): Promise<IClnFundChannelResponse> {
		return this.request('POST', '/v1/fundchannel', {
			id,
			amount: String(amount),
			request_amt: String(requestAmt),
			compact_lease: compactLease
		});
	}

	async closeChannel(
		id: string,
		opts?: { unilateraltimeout?: number }
	): Promise<IClnCloseResponse> {
		const body: Record<string, unknown> = { id };
		if (opts?.unilateraltimeout !== undefined) {
			body.unilateraltimeout = opts.unilateraltimeout;
		}
		return this.request('POST', '/v1/close', body);
	}

	// ── Splicing (requires --experimental-splicing) ──

	/**
	 * Begin a splice on `channelId`. `relativeAmount` is positive to splice-in
	 * (add funds) or negative to splice-out (remove funds). Returns the initial
	 * PSBT to be funded/updated.
	 */
	async spliceInit(
		channelId: string,
		relativeAmount: number,
		opts?: { initialpsbt?: string; feeratePerKw?: number; skipStfu?: boolean }
	): Promise<IClnSpliceInitResponse> {
		const body: Record<string, unknown> = {
			channel_id: channelId,
			relative_amount: relativeAmount
		};
		if (opts?.initialpsbt !== undefined) body.initialpsbt = opts.initialpsbt;
		if (opts?.feeratePerKw !== undefined)
			body.feerate_per_kw = opts.feeratePerKw;
		if (opts?.skipStfu !== undefined) body.skip_stfu = opts.skipStfu;
		return this.request('POST', '/v1/splice_init', body);
	}

	/**
	 * Advance the interactive-tx negotiation. Call repeatedly until the response
	 * has `commitments_secured: true`, feeding the returned PSBT back in.
	 */
	async spliceUpdate(
		channelId: string,
		psbt: string
	): Promise<IClnSpliceUpdateResponse> {
		return this.request('POST', '/v1/splice_update', {
			channel_id: channelId,
			psbt
		});
	}

	/**
	 * Sign and broadcast the splice transaction. Returns the broadcast tx + txid.
	 */
	async spliceSigned(
		psbt: string,
		channelId?: string
	): Promise<IClnSpliceSignedResponse> {
		const body: Record<string, unknown> = { psbt };
		if (channelId !== undefined) body.channel_id = channelId;
		return this.request('POST', '/v1/splice_signed', body);
	}

	// ── Invoices ──

	async createInvoice(
		amountMsat: number | string,
		label: string,
		description: string
	): Promise<IClnInvoice> {
		return this.request('POST', '/v1/invoice', {
			amount_msat: String(amountMsat),
			label,
			description
		});
	}

	async listInvoices(label?: string): Promise<{ invoices: IClnInvoice[] }> {
		const body = label ? { label } : undefined;
		return this.request('POST', '/v1/listinvoices', body);
	}

	// ── Payments ──

	async pay(bolt11: string): Promise<IClnPayResponse> {
		return this.request('POST', '/v1/pay', { bolt11 });
	}

	// ── Wallet ──

	async newAddr(): Promise<IClnNewAddr> {
		return this.request('POST', '/v1/newaddr');
	}

	// ── BOLT 12 Offers ──

	async createOffer(
		amountMsat: number | string | 'any',
		description: string
	): Promise<IClnOfferResponse> {
		return this.request('POST', '/v1/offer', {
			amount: String(amountMsat),
			description
		});
	}

	async fetchInvoice(
		offer: string,
		amountMsat?: number | string
	): Promise<IClnFetchInvoiceResponse> {
		const body: Record<string, unknown> = { offer };
		if (amountMsat !== undefined) {
			body.amount_msat = String(amountMsat);
		}
		return this.request('POST', '/v1/fetchinvoice', body);
	}

	// ── Zero-Conf ──

	async fundZeroConfChannel(
		id: string,
		amount: number | string,
		pushMsat?: number
	): Promise<IClnFundChannelResponse> {
		const body: Record<string, unknown> = {
			id,
			amount: String(amount),
			mindepth: 0
		};
		if (pushMsat !== undefined) {
			body.push_msat = pushMsat;
		}
		return this.request('POST', '/v1/fundchannel', body);
	}
}
