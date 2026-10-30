import {
	decodeRequestEnvelope,
	verifyRequestEnvelope
} from '../lightning/direct-funding/envelope';
import {
	DF_MAX_AMOUNT_SAT,
	DirectFundingError,
	DirectFundingErrorCode,
	chainHashForNetwork,
	malformed
} from '../lightning/direct-funding/types';
import type { IDfRequestEnvelope } from '../lightning/direct-funding/types';
import { DirectFundingSender } from '../lightning/direct-funding/sender/engine';
import type { IDfSendOptions } from '../lightning/direct-funding/sender/engine';
import {
	DF_PAYMENTS_STORAGE_KEY,
	DirectFundingPaymentStore,
	isWellFormedRecord
} from '../lightning/direct-funding/sender/records';
import type { IDfPaymentStoreDeps } from '../lightning/direct-funding/sender/records';
import type {
	IDfPaymentRecord,
	IDfSenderConfig,
	IDfSenderWallet,
	IDfSendResult
} from '../lightning/direct-funding/sender/types';
import { DF_POST_WITNESS_STATES } from '../lightning/direct-funding/sender/types';
import type { DfTransportRegistry } from '../lightning/direct-funding/transport/registry';
import type { DfTransportLog } from '../lightning/direct-funding/transport/types';
import type { Network } from '../lightning/invoice/types';
import { Transaction } from 'bitcoinjs-lib';

/** Writes must finish durably before returning, and must throw on failure. */
export type DirectFundingStorage = NonNullable<IDfPaymentStoreDeps['storage']>;

export interface IDirectFundingWallet extends IDfSenderWallet {
	/** The actual chain used by the wallet and its transaction lookups. */
	readonly network: Network;
	/** Refresh the synchronous wallet view before selecting coins or reconciling. */
	refresh?(fundingTxids?: readonly string[]): Promise<void>;
	/** Drain asynchronous reservation writes before the host closes storage. */
	waitForIdle?(): Promise<void>;
}

export interface IDirectFundingClientOptions {
	wallet: IDirectFundingWallet;
	registry: DfTransportRegistry;
	storage: DirectFundingStorage;
	network: Network;
	config?: IDfSenderConfig;
	log?: DfTransportLog;
}

export interface IDirectFundingRequest {
	encoded: string;
	envelope: IDfRequestEnvelope;
	/** The URI's optional amount, in exact satoshis. */
	uriAmountSat?: bigint;
}

/** Extract only an explicit direct-funding request, never an address fallback. */
export function parseDirectFundingRequest(input: string): {
	encoded: string;
	uriAmountSat?: bigint;
} {
	if (input.length > 32_768) throw malformed('payment request is too long');
	if (!/^bitcoin:/i.test(input)) {
		return { encoded: input };
	}
	if (input.includes('#'))
		throw malformed('payment URI must not have a fragment');
	const query = input.indexOf('?');
	if (query < 0) throw malformed('payment URI has no bgnq request');
	const params = new Map<string, string>();
	for (const part of input.slice(query + 1).split('&')) {
		const eq = part.indexOf('=');
		let key: string;
		let value: string;
		try {
			key = decodeURIComponent(eq < 0 ? part : part.slice(0, eq));
			value = decodeURIComponent(eq < 0 ? '' : part.slice(eq + 1));
		} catch {
			throw malformed('payment URI has invalid percent encoding');
		}
		if (key.startsWith('req-')) {
			throw malformed(`unsupported required payment URI parameter: ${key}`);
		}
		if (params.has(key) && (key === 'bgnq' || key === 'amount')) {
			throw malformed(`duplicate payment URI parameter: ${key}`);
		}
		params.set(key, value);
	}
	const encoded = params.get('bgnq');
	if (!encoded) throw malformed('payment URI has no bgnq request');
	const amount = params.get('amount');
	if (amount === undefined) return { encoded };
	if (!/^\d{1,8}(?:\.\d{1,8})?$/.test(amount)) {
		throw malformed(
			'payment URI amount must be BTC with at most eight decimals'
		);
	}
	const [whole, fraction = ''] = amount.split('.');
	const uriAmountSat =
		BigInt(whole) * 100_000_000n + BigInt(fraction.padEnd(8, '0'));
	if (uriAmountSat <= 0n || uriAmountSat > DF_MAX_AMOUNT_SAT) {
		throw malformed('payment URI amount is out of range');
	}
	return { encoded, uriAmountSat };
}

function strictStorage(storage: DirectFundingStorage): DirectFundingStorage {
	return {
		loadWalletData(key) {
			const raw: unknown = storage.loadWalletData(key);
			if (raw !== null && typeof raw !== 'string') {
				if (raw && typeof (raw as Promise<unknown>).then === 'function') {
					void Promise.resolve(raw).catch(() => undefined);
				}
				throw new Error(
					'direct-funding storage must return a string or null synchronously'
				);
			}
			if (key === DF_PAYMENTS_STORAGE_KEY && raw !== null) {
				let rows: unknown;
				try {
					rows = JSON.parse(raw);
				} catch {
					throw new Error('direct-funding payment storage is corrupt');
				}
				if (!Array.isArray(rows) || !rows.every(isWellFormedRecord)) {
					throw new Error(
						'direct-funding payment storage contains invalid records'
					);
				}
				const ids = rows.map((row: IDfPaymentRecord) => row.requestId);
				if (new Set(ids).size !== ids.length) {
					throw new Error(
						'direct-funding payment storage contains duplicate requests'
					);
				}
				for (const row of rows as IDfPaymentRecord[]) {
					if (DF_POST_WITNESS_STATES.has(row.status)) validateCommitment(row);
				}
			}
			return raw;
		},
		saveWalletData(key, value) {
			const result: unknown = storage.saveWalletData(key, value);
			if (result && typeof (result as Promise<unknown>).then === 'function') {
				// Observe the rejected promise too, but never release a witness on it.
				void Promise.resolve(result).catch(() => undefined);
				throw new Error(
					'direct-funding storage writes must complete synchronously'
				);
			}
		}
	};
}

function validateCommitment(row: IDfPaymentRecord): void {
	const isHex = (value: unknown): value is string =>
		typeof value === 'string' && /^(?:[0-9a-f]{2})+$/i.test(value);
	if (
		!isHex(row.fundingTxid) ||
		row.fundingTxid.length !== 64 ||
		!isHex(row.negotiatedTx) ||
		!Array.isArray(row.witness) ||
		row.witness.length < 1 ||
		row.witness.length > 2 ||
		!row.witness.every(isHex) ||
		!row.attestation ||
		!isHex(row.attestation.signature) ||
		row.attestation.signature.length !== 130
	) {
		throw new Error(
			'direct-funding payment storage is missing a valid signed commitment'
		);
	}
	const tx = Transaction.fromHex(row.negotiatedTx);
	// The engine records the wallet adapter's txid as given, which may not be
	// lowercase.
	const spentTxid = row.spentTxid.toLowerCase();
	if (
		tx.getId() !== row.fundingTxid ||
		tx.ins.filter(
			(input) =>
				Buffer.from(input.hash).reverse().toString('hex') === spentTxid &&
				input.index === row.spentVout
		).length !== 1
	) {
		throw new Error(
			'direct-funding payment storage has an inconsistent transaction'
		);
	}
}

/** One client and one exclusively owned storage scope per wallet. */
export class DirectFundingClient {
	private readonly records: DirectFundingPaymentStore;
	private readonly sender: DirectFundingSender;
	private readonly inflight = new Map<
		string,
		{ identity: string; promise: Promise<IDfSendResult> }
	>();
	private readonly chainHash: Buffer;

	constructor(private readonly options: IDirectFundingClientOptions) {
		if (!options.storage)
			throw new Error('durable payment storage is required');
		if (options.wallet.network !== options.network) {
			throw new Error(
				'wallet network does not match the direct-funding client network'
			);
		}
		this.chainHash = Buffer.from(chainHashForNetwork(options.network));
		this.records = new DirectFundingPaymentStore({
			storage: strictStorage(options.storage)
		});
		this.records.restore();
		this.sender = new DirectFundingSender(
			{
				wallet: options.wallet,
				registry: options.registry,
				payments: this.records,
				chainHash: () => Buffer.from(this.chainHash),
				log: options.log
			},
			options.config
		);
	}

	/** Verify locally without contacting a peer or asking the wallet to sign. */
	inspect(input: string): IDirectFundingRequest {
		const request = this.readRequest(input);
		this.checkUriAmount(request);
		return request;
	}

	private readRequest(input: string): IDirectFundingRequest {
		const parsed = parseDirectFundingRequest(input);
		const envelope = decodeRequestEnvelope(parsed.encoded);
		verifyRequestEnvelope(envelope, {
			expectedChainHash: this.chainHash,
			allowExpired:
				this.records.get(envelope.requestId.toString('hex')) !== null
		});
		const existing = this.records.get(envelope.requestId.toString('hex'));
		const running = this.inflight.get(envelope.requestId.toString('hex'));
		if (
			(existing &&
				(existing.receiverNodeId !== envelope.receiverNodeId.toString('hex') ||
					existing.receiptHash !== envelope.receiptHash.toString('hex'))) ||
			(running && running.identity !== requestIdentity(envelope))
		) {
			throw malformed(
				'request id is already bound to a different receiver or receipt'
			);
		}
		return { ...parsed, envelope };
	}

	private checkUriAmount(request: IDirectFundingRequest): void {
		if (
			request.uriAmountSat !== undefined &&
			request.envelope.amountSat !== undefined &&
			request.uriAmountSat !== request.envelope.amountSat
		) {
			throw new DirectFundingError(
				DirectFundingErrorCode.AMOUNT_MISMATCH,
				'payment URI amount differs from the signed request'
			);
		}
	}

	/** Pay or resume the same request. Never automatically pay its fallback address. */
	pay(input: string, opts: IDfSendOptions = {}): Promise<IDfSendResult> {
		try {
			return this.payRequest(input, opts);
		} catch (err) {
			return Promise.reject(err);
		}
	}

	private payRequest(
		input: string,
		opts: IDfSendOptions
	): Promise<IDfSendResult> {
		const request = this.readRequest(input);
		const id = request.envelope.requestId.toString('hex');
		const running = this.inflight.get(id);
		if (running) return running.promise;
		const existing = this.records.get(id);
		const committed = existing && DF_POST_WITNESS_STATES.has(existing.status);
		const sendOptions = { ...opts };
		if (!committed) this.checkUriAmount(request);
		if (!committed && request.uriAmountSat !== undefined) {
			if (
				opts.amountSat !== undefined &&
				opts.amountSat !== request.uriAmountSat
			) {
				throw new DirectFundingError(
					DirectFundingErrorCode.AMOUNT_MISMATCH,
					'payment amount differs from the payment URI'
				);
			}
			if (request.envelope.amountSat === undefined)
				sendOptions.amountSat = request.uriAmountSat;
		}
		const run = Promise.resolve().then(async () => {
			// Refresh errors cannot turn an already committed payment into a refusal.
			if (!committed) {
				// Recover first, so the refresh sees the coins recovery unlocked.
				await this.sender.recoverReservations();
				await this.refreshWallet();
			}
			return this.sender.send(request.encoded, sendOptions);
		});
		this.inflight.set(id, {
			identity: requestIdentity(request.envelope),
			promise: run
		});
		void run.finally(() => this.inflight.delete(id)).catch(() => undefined);
		return run;
	}

	/** Recover unused reservations and refresh chain facts. Schedule from the host app. */
	async reconcile(): Promise<void> {
		await this.sender.recoverReservations();
		await this.refreshWallet();
		await this.sender.reconcile();
		await this.options.wallet.waitForIdle?.();
	}

	/**
	 * Wait for this client's payments, the reservation releases they started
	 * and the wallet's queued writes to finish. Stop starting payments and
	 * reconciliation first, and call this before closing storage: a timed-out
	 * payment's release can still be running after its pay() settled.
	 */
	async waitForIdle(): Promise<void> {
		do {
			await Promise.allSettled(
				[...this.inflight.values()].map((running) => running.promise)
			);
			await this.sender.waitForReleases();
			await this.options.wallet.waitForIdle?.();
		} while (this.inflight.size > 0);
	}

	/** Detached snapshots so application code cannot mutate the payment journal. */
	payments(): IDfPaymentRecord[] {
		return JSON.parse(
			JSON.stringify(this.records.list())
		) as IDfPaymentRecord[];
	}

	private async refreshWallet(): Promise<void> {
		await this.options.wallet.refresh?.(
			this.records
				.pending()
				.map((record) => record.fundingTxid)
				.filter((id): id is string => !!id)
		);
	}
}

function requestIdentity(envelope: IDfRequestEnvelope): string {
	return `${envelope.receiverNodeId.toString(
		'hex'
	)}:${envelope.receiptHash.toString('hex')}`;
}
