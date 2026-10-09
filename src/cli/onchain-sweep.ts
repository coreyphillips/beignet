import * as bitcoin from 'bitcoinjs-lib';
import type { Wallet } from '../wallet';
import type { SqliteStorage } from '../lightning/storage/sqlite-storage';
import { BeignetError } from './errors';

export const ONCHAIN_SWEEPS_KEY = 'daemon:onchain-sweeps:v1';

export interface OnchainSweepRequest {
	requestId: string;
	address: string;
	satsPerVbyte: number;
	inputOutpoints: Array<{ txid: string; vout: number }>;
	debitSats: number;
	maxFeeSats: number;
}

export interface OnchainSweepInfo {
	requestId: string;
	address: string;
	status:
		| 'preparing'
		| 'prepared'
		| 'submitted'
		| 'confirmed'
		| 'cancelling'
		| 'cancelled';
	debitSats: number;
	amountSats?: number;
	feeSats?: number;
	satsPerVbyte?: number;
	txid?: string;
	createdAt: number;
	broadcastAccepted?: boolean;
	error?: string;
}

interface SweepRecord extends OnchainSweepInfo {
	request: OnchainSweepRequest;
	hex?: string;
}

type SweepStorage = Pick<SqliteStorage, 'loadWalletData' | 'saveWalletData'>;
type SweepWallet = Pick<
	Wallet,
	| 'data'
	| 'transaction'
	| 'isWatchOnly'
	| 'isMultisig'
	| 'transactions'
	| 'freezeUtxoIfUnfrozen'
	| 'unfreezeUtxoIfTagged'
	| 'listFrozenUtxos'
	| 'getWalletDataKey'
	| 'resetSendTransaction'
>;

function refuse(code: string, message: string): never {
	throw new BeignetError(code, message);
}

function requestId(value: unknown): asserts value is string {
	if (typeof value !== 'string' || !/^[a-zA-Z0-9_-]{8,128}$/.test(value))
		refuse('INVALID_PARAMS', 'A stable sweep requestId is required');
}

function normalize(
	input: OnchainSweepRequest,
	network: bitcoin.Network
): OnchainSweepRequest {
	requestId(input?.requestId);
	if (typeof input.address !== 'string' || !input.address)
		refuse('INVALID_PARAMS', 'A sweep address is required');
	try {
		bitcoin.address.toOutputScript(input.address, network);
	} catch {
		refuse('INVALID_PARAMS', 'Invalid sweep address for this network');
	}
	if (
		!Number.isFinite(input.satsPerVbyte) ||
		input.satsPerVbyte <= 0 ||
		!Number.isSafeInteger(input.debitSats) ||
		input.debitSats <= 0 ||
		!Number.isSafeInteger(input.maxFeeSats) ||
		input.maxFeeSats < 0 ||
		input.maxFeeSats >= input.debitSats
	)
		refuse('INVALID_PARAMS', 'Invalid sweep amount or fee bounds');
	if (
		!Array.isArray(input.inputOutpoints) ||
		!input.inputOutpoints.length ||
		input.inputOutpoints.length > 10000
	)
		refuse('INVALID_PARAMS', 'The reviewed sweep inputs are required');
	const inputs = input.inputOutpoints
		.map((point) => {
			if (
				!point ||
				typeof point.txid !== 'string' ||
				!/^[a-fA-F0-9]{64}$/.test(point.txid) ||
				!Number.isInteger(point.vout) ||
				point.vout < 0 ||
				point.vout > 0xffffffff
			)
				refuse('INVALID_PARAMS', 'Invalid sweep input');
			return { txid: point.txid.toLowerCase(), vout: point.vout };
		})
		.sort((a, b) => a.txid.localeCompare(b.txid) || a.vout - b.vout);
	if (
		new Set(inputs.map((point) => `${point.txid}:${point.vout}`)).size !==
		inputs.length
	)
		refuse('INVALID_PARAMS', 'Duplicate sweep input');
	return {
		requestId: input.requestId,
		address: input.address,
		satsPerVbyte: input.satsPerVbyte,
		inputOutpoints: inputs,
		debitSats: input.debitSats,
		maxFeeSats: input.maxFeeSats
	};
}

/** Called under the node's on-chain send lock. Stored hex is never rebuilt on submit. */
export class OnchainSweeps {
	constructor(
		private readonly deps: {
			storage: SweepStorage;
			wallet: SweepWallet;
			network: bitcoin.Network;
			broadcast: (hex: string) => Promise<unknown>;
			admitAndSave: (debitSats: number, save: () => void) => void;
		}
	) {}

	private records(): SweepRecord[] {
		const raw = this.deps.storage.loadWalletData(ONCHAIN_SWEEPS_KEY);
		if (raw === null) return [];
		try {
			const records = JSON.parse(raw) as SweepRecord[];
			if (!Array.isArray(records) || records.length > 1000)
				throw new Error('Invalid sweep journal');
			for (const record of records) {
				const normalized = normalize(record.request, this.deps.network);
				if (
					record.requestId !== normalized.requestId ||
					record.address !== normalized.address ||
					record.debitSats !== normalized.debitSats ||
					!Number.isSafeInteger(record.createdAt) ||
					![
						'preparing',
						'prepared',
						'submitted',
						'confirmed',
						'cancelling',
						'cancelled'
					].includes(record.status)
				)
					throw new Error('Invalid sweep record');
				if (['prepared', 'submitted', 'confirmed'].includes(record.status))
					this.verifyTransaction(record);
			}
			if (
				new Set(records.map((record) => record.requestId)).size !==
				records.length
			)
				throw new Error('Duplicate sweep identity');
			return records;
		} catch {
			return refuse(
				'SWEEP_JOURNAL_INVALID',
				'The sweep journal cannot be read safely'
			);
		}
	}

	private save(record: SweepRecord): void {
		const records = this.records();
		const index = records.findIndex(
			(entry) => entry.requestId === record.requestId
		);
		if (index < 0) {
			if (records.length >= 1000)
				refuse('SWEEP_JOURNAL_FULL', 'The sweep journal is full');
			records.push(record);
		} else records[index] = record;
		this.deps.storage.saveWalletData(
			ONCHAIN_SWEEPS_KEY,
			JSON.stringify(records)
		);
	}

	private publicInfo(record: SweepRecord): OnchainSweepInfo {
		const { request, hex, ...info } = record;
		void request;
		void hex;
		if (record.hex && record.feeSats !== undefined)
			info.satsPerVbyte =
				record.feeSats / bitcoin.Transaction.fromHex(record.hex).virtualSize();
		if (['submitted', 'confirmed'].includes(record.status) && record.txid) {
			const transaction = this.deps.wallet.transactions[record.txid];
			info.status =
				transaction &&
				transaction.exists !== false &&
				typeof transaction.height === 'number' &&
				Number.isFinite(transaction.height) &&
				transaction.height > 0
					? 'confirmed'
					: 'submitted';
		}
		return info;
	}

	get(id: string): OnchainSweepInfo | null {
		requestId(id);
		const record = this.records().find((entry) => entry.requestId === id);
		return record ? this.publicInfo(record) : null;
	}

	list(): OnchainSweepInfo[] {
		return this.records().map((record) => this.publicInfo(record));
	}

	assertInputMutable(txid: string, vout: number): void {
		if (
			this.records().some(
				(record) =>
					record.status !== 'cancelled' &&
					record.request.inputOutpoints.some(
						(point) => point.txid === txid.toLowerCase() && point.vout === vout
					)
			)
		)
			refuse(
				'SWEEP_INPUT_RESERVED',
				'This input belongs to a durable sweep; only cancellation before submission can release it'
			);
	}

	assertRestorable(): void {
		if (
			this.list().some(
				(record) => !['confirmed', 'cancelled'].includes(record.status)
			)
		)
			refuse(
				'SWEEP_PENDING',
				'Resolve or cancel active on-chain sweeps before replacing the wallet database'
			);
	}

	/** Preserve signed-input ownership if recovery installs an older wallet database. */
	carryTo(target: SweepStorage & Pick<SqliteStorage, 'transaction'>): void {
		this.assertRestorable();
		const records = this.records();
		if (!records.length) return;
		const journal = this.deps.storage.loadWalletData(ONCHAIN_SWEEPS_KEY)!;
		const existingJournal = target.loadWalletData(ONCHAIN_SWEEPS_KEY);
		if (existingJournal !== null && existingJournal !== journal)
			refuse(
				'SWEEP_JOURNAL_CONFLICT',
				'The restored database has a different sweep journal'
			);
		const key = this.deps.wallet.getWalletDataKey('blacklistedUtxos');
		const parse = (
			raw: string | null
		): ReturnType<SweepWallet['listFrozenUtxos']> => {
			try {
				const entries = raw === null ? [] : JSON.parse(raw);
				if (
					!Array.isArray(entries) ||
					entries.some(
						(entry) =>
							!entry ||
							typeof entry.tx_hash !== 'string' ||
							!/^[a-fA-F0-9]{64}$/.test(entry.tx_hash) ||
							!Number.isInteger(entry.tx_pos) ||
							entry.tx_pos < 0
					)
				)
					throw new Error('Invalid reservations');
				return entries;
			} catch {
				return refuse(
					'SWEEP_JOURNAL_INVALID',
					'Sweep reservations cannot be read safely'
				);
			}
		};
		const source = parse(this.deps.storage.loadWalletData(key));
		const merged = parse(target.loadWalletData(key));
		for (const record of records.filter((item) =>
			['submitted', 'confirmed'].includes(item.status)
		)) {
			for (const point of record.request.inputOutpoints) {
				const matches = (entry: (typeof source)[number]) =>
					entry.tx_hash === point.txid && entry.tx_pos === point.vout;
				const held = source.find(
					(entry) =>
						matches(entry) && entry.freezeTag === this.tag(record.requestId)
				);
				if (!held)
					refuse(
						'SWEEP_JOURNAL_INVALID',
						'A signed sweep is missing its durable input reservation'
					);
				if (
					merged.some(
						(entry) => matches(entry) && entry.freezeTag !== held.freezeTag
					)
				)
					refuse(
						'SWEEP_JOURNAL_CONFLICT',
						'A restored input belongs to another reservation'
					);
				if (!merged.some(matches)) merged.push(held);
			}
		}
		target.transaction(() => {
			target.saveWalletData(key, JSON.stringify(merged));
			target.saveWalletData(ONCHAIN_SWEEPS_KEY, journal);
		});
	}

	private tag(id: string): string {
		return `onchain-sweep:${id}`;
	}

	private resolveInputs(record: SweepRecord) {
		const wallet = this.deps.wallet;
		return record.request.inputOutpoints.map((point) => {
			const input = wallet.data.utxos.find(
				(coin) => coin.tx_hash === point.txid && coin.tx_pos === point.vout
			);
			if (!input)
				return refuse(
					'SWEEP_INPUT_UNAVAILABLE',
					'A reviewed sweep input is no longer in this wallet'
				);
			const freezes = wallet
				.listFrozenUtxos()
				.filter(
					(coin) => coin.tx_hash === point.txid && coin.tx_pos === point.vout
				);
			if (freezes.some((coin) => coin.freezeTag !== this.tag(record.requestId)))
				return refuse(
					'SWEEP_INPUT_UNAVAILABLE',
					'A reviewed sweep input is frozen or pledged to another operation'
				);
			return input;
		});
	}

	private async reserve(record: SweepRecord): Promise<void> {
		this.resolveInputs(record);
		for (const point of record.request.inputOutpoints) {
			const result = await this.deps.wallet.freezeUtxoIfUnfrozen({
				txid: point.txid,
				index: point.vout,
				tag: this.tag(record.requestId)
			});
			if (result.isErr()) refuse('SWEEP_NOT_PERSISTED', result.error.message);
			// A competing freeze can win while the wallet's write lock is awaited.
			this.resolveInputs(record);
		}
	}

	private async release(record: SweepRecord): Promise<void> {
		for (const point of record.request.inputOutpoints) {
			const result = await this.deps.wallet.unfreezeUtxoIfTagged({
				txid: point.txid,
				index: point.vout,
				tag: this.tag(record.requestId)
			});
			if (result.isErr()) refuse('SWEEP_NOT_PERSISTED', result.error.message);
		}
	}

	private verifyTransaction(record: SweepRecord): bitcoin.Transaction {
		if (!record.hex)
			return refuse('SWEEP_JOURNAL_INVALID', 'Missing signed sweep');
		const tx = bitcoin.Transaction.fromHex(record.hex);
		const expected = record.request.inputOutpoints
			.map((point) => `${point.txid}:${point.vout}`)
			.sort();
		const actual = tx.ins
			.map(
				(input) =>
					`${Buffer.from(input.hash).reverse().toString('hex')}:${input.index}`
			)
			.sort();
		const script = bitcoin.address.toOutputScript(
			record.address,
			this.deps.network
		);
		const fee =
			record.debitSats - tx.outs.reduce((sum, output) => sum + output.value, 0);
		if (
			JSON.stringify(expected) !== JSON.stringify(actual) ||
			tx.outs.length !== 1 ||
			!tx.outs[0].script.equals(script) ||
			tx.outs[0].value <= 0 ||
			fee < 0 ||
			fee > record.request.maxFeeSats ||
			(record.txid !== undefined && record.txid !== tx.getId()) ||
			(record.amountSats !== undefined &&
				record.amountSats !== tx.outs[0].value) ||
			(record.feeSats !== undefined && record.feeSats !== fee)
		)
			return refuse(
				'SWEEP_QUOTE_EXPIRED',
				'The signed sweep no longer matches the reviewed inputs, output or fee'
			);
		return tx;
	}

	async prepare(input: OnchainSweepRequest): Promise<OnchainSweepInfo> {
		const request = normalize(input, this.deps.network);
		const existing = this.records().find(
			(record) => record.requestId === request.requestId
		);
		if (
			existing &&
			JSON.stringify(existing.request) !== JSON.stringify(request)
		)
			return refuse(
				'REQUEST_ID_CONFLICT',
				'This sweep requestId already belongs to another sweep'
			);
		if (existing && existing.status !== 'preparing')
			return this.publicInfo(existing);
		const wallet = this.deps.wallet;
		if (wallet.isWatchOnly || wallet.isMultisig)
			return refuse(
				'SWEEP_UNAVAILABLE',
				'This wallet cannot sign an on-chain sweep'
			);
		const record: SweepRecord = existing ?? {
			requestId: request.requestId,
			request,
			address: request.address,
			status: 'preparing',
			debitSats: request.debitSats,
			createdAt: Date.now()
		};
		const inputs = this.resolveInputs(record);
		if (inputs.reduce((sum, coin) => sum + coin.value, 0) !== request.debitSats)
			return refuse(
				'SWEEP_QUOTE_EXPIRED',
				'The reviewed sweep input value changed'
			);
		if (!existing) this.save(record);
		await this.reserve(record);
		try {
			await wallet.resetSendTransaction();
			const setup = await wallet.transaction.setupTransaction({
				utxos: inputs,
				rbf: false,
				satsPerByte: request.satsPerVbyte
			});
			if (setup.isErr()) return refuse('SEND_FAILED', setup.error.message);
			const sweep = await wallet.transaction.sendMax({
				address: request.address,
				satsPerByte: request.satsPerVbyte,
				rbf: false,
				// reserve() froze these inputs for this sweep.
				spendFrozen: true
			});
			if (sweep.isErr()) return refuse('SEND_FAILED', sweep.error.message);
			const built = await wallet.transaction.createTransaction({
				shuffleOutputs: false
			});
			if (built.isErr()) return refuse('SEND_FAILED', built.error.message);
			this.resolveInputs(record);
			record.hex = built.value.hex;
			const tx = this.verifyTransaction(record);
			record.txid = tx.getId();
			record.amountSats = tx.outs[0].value;
			record.feeSats = record.debitSats - record.amountSats;
			record.status = 'prepared';
			this.save(record);
			return this.publicInfo(record);
		} finally {
			await wallet.resetSendTransaction();
		}
	}

	async submit(id: string): Promise<OnchainSweepInfo> {
		requestId(id);
		const record = this.records().find((entry) => entry.requestId === id);
		if (!record) return refuse('NOT_FOUND', 'Sweep not found');
		if (['cancelled', 'cancelling', 'preparing'].includes(record.status))
			return refuse('SWEEP_NOT_PREPARED', 'The sweep is not ready to submit');
		if (this.publicInfo(record).status === 'confirmed') {
			record.status = 'confirmed';
			this.save(record);
			// Keep the spent outpoints reserved if a later reorg returns them.
			return this.publicInfo(record);
		}
		this.verifyTransaction(record);
		if (record.status === 'prepared') {
			await this.reserve(record);
			record.status = 'submitted';
			this.deps.admitAndSave(record.debitSats, () => this.save(record));
		} else if (record.status === 'confirmed') {
			record.status = 'submitted';
			this.save(record);
		}
		try {
			await this.deps.broadcast(record.hex!);
			record.broadcastAccepted = true;
			delete record.error;
		} catch (error) {
			record.error = String((error as Error).message ?? error).slice(0, 300);
		}
		this.save(record);
		return this.publicInfo(record);
	}

	async cancel(id: string): Promise<OnchainSweepInfo> {
		requestId(id);
		const record = this.records().find((entry) => entry.requestId === id);
		if (!record) return refuse('NOT_FOUND', 'Sweep not found');
		if (record.status === 'submitted' || record.status === 'confirmed')
			return refuse(
				'SWEEP_ALREADY_SUBMITTED',
				'A submitted sweep cannot be cancelled'
			);
		record.status = 'cancelling';
		this.save(record);
		await this.release(record);
		record.status = 'cancelled';
		this.save(record);
		return this.publicInfo(record);
	}
}
