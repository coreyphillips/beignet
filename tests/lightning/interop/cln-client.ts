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
		opts?: { unilateraltimeout?: number; destination?: string }
	): Promise<IClnCloseResponse> {
		const body: Record<string, unknown> = { id };
		if (opts?.unilateraltimeout !== undefined) {
			body.unilateraltimeout = opts.unilateraltimeout;
		}
		if (opts?.destination !== undefined) {
			body.destination = opts.destination;
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

	// ── v2 (dual-funded) opens and their RBF ──

	/**
	 * Reserve wallet UTXOs and return a PSBT funding `amount`. The starting
	 * point for both openchannel_init and openchannel_bump.
	 */
	async fundPsbt(
		satoshi: number | string,
		feerate: string,
		startweight = 250
	): Promise<{ psbt: string; feerate_per_kw?: number }> {
		return this.request('POST', '/v1/fundpsbt', {
			satoshi: String(satoshi),
			feerate,
			startweight,
			// Without this the reserved UTXO's remainder is left as fee, which
			// for a wallet-sized UTXO trips bitcoind's maxtxfee at broadcast.
			excess_as_change: true
		});
	}

	/**
	 * Build a PSBT from SPECIFIC utxos ("txid:vout"). The RBF recipe: a
	 * replacement must double-spend the previous attempt, so it is funded from
	 * that attempt's own inputs, which are still reserved for it
	 * (`reservedok`).
	 */
	async utxoPsbt(
		satoshi: number | string,
		feerate: string,
		utxos: string[],
		startweight = 250
	): Promise<{ psbt: string }> {
		return this.request('POST', '/v1/utxopsbt', {
			satoshi: String(satoshi),
			feerate,
			startweight,
			utxos,
			reservedok: true,
			excess_as_change: true
		});
	}

	/** Begin a v2 (dual-funded) open toward `id` with `amount` from initialpsbt. */
	async openChannelInit(
		id: string,
		amount: number | string,
		initialpsbt: string,
		opts?: { feeratePerKw?: number }
	): Promise<{
		channel_id: string;
		psbt: string;
		commitments_secured: boolean;
	}> {
		const body: Record<string, unknown> = {
			id,
			amount: String(amount),
			initialpsbt
		};
		if (opts?.feeratePerKw !== undefined) {
			body.funding_feerate = `${opts.feeratePerKw}perkw`;
		}
		return this.request('POST', '/v1/openchannel_init', body);
	}

	/**
	 * Start an RBF of an unconfirmed v2 open. `amount` may differ from the
	 * original attempt (BOLT 2 allows a different funding_output_contribution
	 * per attempt). Only valid before the channel locks in, and the feerate
	 * must clear the peer's 25/24 floor, so pass it explicitly rather than
	 * relying on CLN's 65/64 default.
	 */
	async openChannelBump(
		channelId: string,
		amount: number | string,
		initialpsbt: string,
		opts?: { feeratePerKw?: number }
	): Promise<{
		channel_id: string;
		psbt: string;
		commitments_secured: boolean;
	}> {
		const body: Record<string, unknown> = {
			channel_id: channelId,
			amount: String(amount),
			initialpsbt
		};
		if (opts?.feeratePerKw !== undefined) {
			body.funding_feerate = `${opts.feeratePerKw}perkw`;
		}
		return this.request('POST', '/v1/openchannel_bump', body);
	}

	/**
	 * Advance the open's interactive-tx negotiation. Call repeatedly, feeding
	 * the returned PSBT back in, until `commitments_secured` is true.
	 */
	async openChannelUpdate(
		channelId: string,
		psbt: string
	): Promise<{
		channel_id: string;
		psbt: string;
		commitments_secured: boolean;
	}> {
		return this.request('POST', '/v1/openchannel_update', {
			channel_id: channelId,
			psbt
		});
	}

	/** Sign our inputs of a PSBT the wallet reserved. */
	async signPsbt(psbt: string): Promise<{ signed_psbt: string }> {
		return this.request('POST', '/v1/signpsbt', { psbt });
	}

	/** Send our tx_signatures for the (bumped) open. */
	async openChannelSigned(
		channelId: string,
		signedPsbt: string
	): Promise<{ channel_id: string; tx: string; txid: string }> {
		return this.request('POST', '/v1/openchannel_signed', {
			channel_id: channelId,
			signed_psbt: signedPsbt
		});
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
