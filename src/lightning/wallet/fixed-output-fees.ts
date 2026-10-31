import * as bitcoin from 'bitcoinjs-lib';
import type { IWalletLike, ISpliceUtxo } from './wallet-funding-provider';
import type { IFeeBumpSelectionOpts } from '../node/types';
import type { ISpliceWalletInput } from '../channel/channel';
import type { ILedgerKeyValueStorage } from '../storage/durable-ledger';
import { EAddressType } from '../../types';
import { getECPair } from '../../utils/ecc-apis';
import { parseFixedOutputHtlcFeeActionId } from '../chain/types';
import { P2WPKH_INPUT_WEIGHT, spliceFeeSats } from '../channel/splice-weight';

/** Explicit wallet-wide lifetime fee limits. Retirement releases coins, never budget. */
export interface IFixedOutputFeePolicy {
	storage: ILedgerKeyValueStorage;
	/** Defaults to Wallet.id. The same wallet must use the same identity after restart. */
	walletId?: string;
	/** Maximum wallet value burned by any one HTLC action, including replacements. */
	maxFeeSatoshis: bigint;
	/** Sum of all action caps plus preparation fees, including unfinished reservations. */
	maxTotalFeeSatoshis: bigint;
	/** Upper bound reserved before each preparation; replaced by its exact fee before signing. */
	maxPreparationFeeSatoshis: bigint;
	/** Number of equal owned fee outputs prepared together, from 1 through 16. Default 4. */
	feeCoinCount?: number;
	/** Preparation feerate in sat/vByte. Default 1. */
	preparationFeeRatePerVbyte?: number;
}

export class FixedOutputFeePreparationPendingError extends Error {
	readonly code = 'FEE_PREPARATION_PENDING';
	constructor(readonly transactionId: string) {
		super(
			'Fixed-output fee preparation is awaiting wallet visibility or confirmation'
		);
		this.name = 'FixedOutputFeePreparationPendingError';
	}
}

type Coin = { utxo: ISpliceUtxo; previous: string };
type Preparation = {
	id: string;
	state: 'building' | 'unsigned' | 'signed' | 'published';
	source: Coin;
	address: string;
	amount: number;
	count: number;
	fee: string;
	observed?: boolean;
	unsigned?: string;
	signed?: string;
};
type Journal = {
	version: 1;
	identity: string;
	actions: Record<
		string,
		{
			cap: string;
			inputs: Coin[];
			feeActionId?: string;
			retired?: boolean;
			released?: boolean;
		}
	>;
	preparations: Preparation[];
};
interface Host {
	previousTransactions(ids: readonly string[]): Promise<Map<string, string>>;
	input(coin: ISpliceUtxo, previous: string): ISpliceWalletInput;
	pledge(txid: string, index: number, tag: string): Promise<void>;
	release(txid: string, index: number, tag: string): Promise<void>;
}
const key = (coin: Pick<ISpliceUtxo, 'tx_hash' | 'tx_pos'>): string =>
	`${coin.tx_hash.toLowerCase()}:${coin.tx_pos}`;
const copy = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;
const positive = (value: bigint): boolean =>
	typeof value === 'bigint' &&
	value > 0n &&
	value <= BigInt(Number.MAX_SAFE_INTEGER);

/** A bounded, wallet-scoped preparation journal. Caller holds the provider operation lock. */
export class FixedOutputFeePool {
	private readonly identity: string;
	private readonly storageKey: string;
	private readonly prefix: string;
	private readonly network: bitcoin.Network;
	private journal: Journal;
	private encoded: string | null;
	/** A failed durable write keeps the exact signed bytes for the next in-process retry. */
	private unsavedSigned = new Map<string, string>();

	constructor(
		private readonly wallet: IWalletLike,
		private readonly policy: IFixedOutputFeePolicy,
		private readonly host: Host
	) {
		this.policy = { ...policy };
		const identity = policy.walletId ?? wallet.id;
		if (
			!identity ||
			identity.length > 256 ||
			!positive(policy.maxFeeSatoshis) ||
			!positive(policy.maxTotalFeeSatoshis) ||
			!positive(policy.maxPreparationFeeSatoshis) ||
			policy.maxTotalFeeSatoshis < policy.maxFeeSatoshis ||
			!Number.isInteger(policy.feeCoinCount ?? 4) ||
			(policy.feeCoinCount ?? 4) < 1 ||
			(policy.feeCoinCount ?? 4) > 16 ||
			!Number.isFinite(policy.preparationFeeRatePerVbyte ?? 1) ||
			(policy.preparationFeeRatePerVbyte ?? 1) < 1 ||
			(policy.preparationFeeRatePerVbyte ?? 1) > 10000 ||
			!policy.storage?.transaction ||
			!policy.storage?.loadMetadata ||
			!policy.storage?.saveMetadata ||
			!wallet.withSendLock ||
			!wallet.unfreezeUtxoIfTagged ||
			!wallet.signPsbtWithOurKey ||
			!wallet.importSignedPsbt ||
			!wallet.listUtxos ||
			!wallet.getChangeAddress ||
			!wallet.refreshWallet ||
			!wallet.freezeUtxoIfUnfrozen ||
			!wallet.listFrozenUtxos ||
			!wallet.isUtxoFrozen ||
			!wallet.getAddressFromScriptHash ||
			!wallet.getPrivateKey
		)
			throw new Error(
				'Fixed-output fee preparation requires a durable bounded policy and capable wallet'
			);
		this.identity = `${wallet.network ?? 'bitcoin'}:${identity}`;
		this.prefix =
			'fixed-output-fees:' +
			bitcoin.crypto.sha256(Buffer.from(this.identity)).toString('hex');
		this.storageKey = this.prefix + ':journal';
		this.network =
			wallet.network === 'regtest'
				? bitcoin.networks.regtest
				: wallet.network === 'bitcoin' || !wallet.network
				? bitcoin.networks.bitcoin
				: bitcoin.networks.testnet;
		this.encoded = policy.storage.loadMetadata(this.storageKey);
		this.journal = this.decode(this.encoded);
		this.assertBudget(this.journal);
	}

	private decode(raw: string | null): Journal {
		if (raw === null)
			return {
				version: 1,
				identity: this.identity,
				actions: {},
				preparations: []
			};
		const data = JSON.parse(raw) as Journal;
		if (
			data.version !== 1 ||
			data.identity !== this.identity ||
			!data.actions ||
			!Array.isArray(data.preparations)
		)
			throw new Error('Invalid fixed-output fee journal');
		return data;
	}
	private assertBudget(data: Journal): void {
		let total = 0n;
		for (const [id, action] of Object.entries(data.actions)) {
			if (
				action.feeActionId !== undefined &&
				bitcoin.crypto
					.sha256(Buffer.from(action.feeActionId))
					.toString('hex') !== id
			)
				throw new Error('Fixed-output action identity mismatch');
			const cap = BigInt(action.cap);
			if (
				!positive(cap) ||
				cap > this.policy.maxFeeSatoshis ||
				!Array.isArray(action.inputs)
			)
				throw new Error('Invalid fixed-output action reservation');
			total += cap;
		}
		for (const preparation of data.preparations) {
			const fee = BigInt(preparation.fee);
			if (fee < 0n || fee > this.policy.maxPreparationFeeSatoshis)
				throw new Error('Invalid fixed-output preparation reservation');
			total += fee;
		}
		if (total > this.policy.maxTotalFeeSatoshis)
			throw new Error('Fixed-output lifetime fee budget exhausted');
	}
	private save(next: Journal): void {
		this.assertBudget(next);
		const encoded = JSON.stringify(next);
		this.policy.storage.transaction(() => {
			if (this.policy.storage.loadMetadata(this.storageKey) !== this.encoded)
				throw new Error('Concurrent fixed-output fee journal change');
			this.policy.storage.saveMetadata(this.storageKey, encoded);
			if (this.policy.storage.loadMetadata(this.storageKey) !== encoded)
				throw new Error('Fixed-output fee journal write was not acknowledged');
		});
		this.journal = copy(next);
		this.encoded = encoded;
	}
	private updatePreparation(id: string, update: Partial<Preparation>): void {
		const next = copy(this.journal),
			row = next.preparations.find((p) => p.id === id);
		if (!row) throw new Error('Missing fixed-output preparation');
		Object.assign(row, update);
		this.save(next);
	}
	private latestReservations(): Journal {
		const data = this.decode(this.policy.storage.loadMetadata(this.storageKey));
		this.assertBudget(data);
		return data;
	}
	isReserved(txid: string, index: number): boolean {
		return this.reservedOutpoints().has(`${txid.toLowerCase()}:${index}`);
	}
	reservedOutpoints(): Set<string> {
		const journal = this.latestReservations();
		return new Set([
			...Object.values(journal.actions)
				.filter((a) => !a.released)
				.flatMap((a) => a.inputs.map((c) => key(c.utxo))),
			...journal.preparations.map((p) => key(p.source.utxo))
		]);
	}
	reservationTag(txid: string, index: number): string | undefined {
		for (const [id, action] of Object.entries(
			this.latestReservations().actions
		))
			if (
				!action.released &&
				action.inputs.some(
					(c) => key(c.utxo) === `${txid.toLowerCase()}:${index}`
				)
			)
				return this.prefix + ':action:' + id;
		return undefined;
	}
	ownsFreeze(txid: string, index: number, tag?: string): boolean {
		return tag !== undefined && this.reservationTag(txid, index) === tag;
	}
	/** Enumerate only canonical native HTLC identities authenticated by the journal key. */
	actionIds(channelId: Buffer): readonly string[] {
		if (!Buffer.isBuffer(channelId) || channelId.length !== 32)
			throw new Error('Invalid fixed-output channel identity');
		return Object.entries(this.latestReservations().actions).flatMap(
			([id, action]) => {
				const value = action.feeActionId;
				if (
					action.released ||
					!value ||
					bitcoin.crypto.sha256(Buffer.from(value)).toString('hex') !== id
				)
					return [];
				const parsed = parseFixedOutputHtlcFeeActionId(value);
				return parsed?.channelId.equals(channelId) ? [value] : [];
			}
		);
	}
	private reload(): void {
		const latest = this.policy.storage.loadMetadata(this.storageKey);
		if (latest !== this.encoded) {
			this.journal = this.decode(latest);
			this.encoded = latest;
			this.assertBudget(this.journal);
		}
	}
	private async completeRetirements(): Promise<void> {
		for (const [id, action] of Object.entries(this.journal.actions)) {
			if (!action.retired || action.released) continue;
			for (const coin of action.inputs)
				await this.host.release(
					coin.utxo.tx_hash,
					coin.utxo.tx_pos,
					this.prefix + ':action:' + id
				);
			const next = copy(this.journal);
			next.actions[id].released = true;
			this.save(next);
		}
	}
	/** Caller must establish irrevocable resolution before retiring an action. */
	async retire(feeActionId: string): Promise<void> {
		if (
			typeof feeActionId !== 'string' ||
			!feeActionId ||
			feeActionId.length > 512
		)
			throw new Error('Invalid fixed-output fee action');
		await this.wallet.withSendLock!(async () => {
			this.reload();
			const id = bitcoin.crypto
					.sha256(Buffer.from(feeActionId))
					.toString('hex'),
				action = this.journal.actions[id];
			if (!action) return;
			if (!action.retired) {
				const next = copy(this.journal);
				next.actions[id].retired = true;
				next.actions[id].feeActionId = feeActionId;
				this.save(next);
			}
			await this.completeRetirements();
		});
	}
	private owner(script: Buffer): {
		address: string;
		path: string;
		publicKey: string;
	} {
		const owner = this.wallet.getAddressFromScriptHash!(
			Buffer.from(bitcoin.crypto.sha256(script)).reverse().toString('hex')
		);
		if (
			!owner ||
			!bitcoin.address
				.toOutputScript(owner.address, this.network)
				.equals(script) ||
			!bitcoin.payments
				.p2wpkh({ pubkey: Buffer.from(owner.publicKey, 'hex') })
				.output!.equals(script)
		)
			throw new Error('Fixed-output split has an unowned P2WPKH output');
		return owner;
	}
	private checkCoin(coin: Coin): void {
		const tx = bitcoin.Transaction.fromHex(coin.previous),
			out = tx.outs[coin.utxo.tx_pos];
		const script = bitcoin.address.toOutputScript(
			coin.utxo.address,
			this.network
		);
		const pubkey = Buffer.from(coin.utxo.publicKey, 'hex');
		const owner = this.owner(script);
		if (
			owner.path !== coin.utxo.path ||
			owner.publicKey !== coin.utxo.publicKey ||
			tx.getId() !== coin.utxo.tx_hash.toLowerCase() ||
			!out ||
			!Number.isSafeInteger(coin.utxo.value) ||
			coin.utxo.value <= 0 ||
			out.value !== coin.utxo.value ||
			!out.script.equals(script) ||
			!bitcoin.payments.p2wpkh({ pubkey }).output!.equals(script)
		)
			throw new Error(
				'Fixed-output fee source is not an authenticated owned P2WPKH coin'
			);
	}
	private async refresh(): Promise<void> {
		const result = await this.wallet.refreshWallet!({});
		if (result.isErr())
			throw new Error('Fixed-output fee wallet refresh failed');
	}
	private async freeze(txid: string, vout: number, tag: string): Promise<void> {
		const result = await this.wallet.freezeUtxoIfUnfrozen!({
			txid,
			index: vout,
			tag
		});
		if (
			result.isErr() ||
			!this.wallet.listFrozenUtxos!().some(
				(coin) =>
					coin.tx_hash === txid &&
					coin.tx_pos === vout &&
					coin.freezeTag === tag
			)
		)
			throw new Error(
				'Fixed-output fee reservation belongs to another owner or was refused'
			);
	}
	private validateUnsigned(row: Preparation): bitcoin.Psbt {
		this.checkCoin(row.source);
		const psbt = bitcoin.Psbt.fromBase64(row.unsigned!);
		const source = bitcoin.Transaction.fromHex(row.source.previous);
		const target = bitcoin.address.toOutputScript(row.address, this.network);
		this.owner(target);
		const prevout = psbt.data.inputs[0]?.witnessUtxo;
		if (
			psbt.txInputs.length !== 1 ||
			!psbt.txInputs[0].hash.equals(source.getHash()) ||
			psbt.txInputs[0].index !== row.source.utxo.tx_pos ||
			!prevout ||
			prevout.value !== row.source.utxo.value ||
			!prevout.script.equals(source.outs[row.source.utxo.tx_pos].script)
		)
			throw new Error('Fixed-output split selected an unapproved input');
		if (
			!Number.isInteger(row.count) ||
			row.count < 1 ||
			row.count > 16 ||
			!Number.isSafeInteger(row.amount) ||
			row.amount < 330 ||
			psbt.txOutputs.length < row.count ||
			psbt.txOutputs.length > row.count + 1 ||
			psbt.txOutputs
				.slice(0, row.count)
				.some((o) => o.value !== row.amount || !o.script.equals(target))
		)
			throw new Error('Fixed-output split changed its fee coins');
		for (const output of psbt.txOutputs) this.owner(output.script);
		const fee =
			BigInt(row.source.utxo.value) -
			psbt.txOutputs.reduce((sum, o) => sum + BigInt(o.value), 0n);
		if (
			fee !== BigInt(row.fee) ||
			fee < 0n ||
			fee > this.policy.maxPreparationFeeSatoshis
		)
			throw new Error('Fixed-output split exceeds preparation fee cap');
		return psbt;
	}
	private validateSigned(
		row: Preparation,
		signed: string
	): bitcoin.Transaction {
		const psbt = this.validateUnsigned(row),
			tx = bitcoin.Transaction.fromHex(signed);
		if (
			tx.getId() !==
			bitcoin.Transaction.fromBuffer(psbt.data.getTransaction()).getId()
		)
			throw new Error(
				'Fixed-output wallet signer changed the split transaction'
			);
		const witness = tx.ins[0].witness;
		if (
			witness.length !== 2 ||
			!witness[1].equals(Buffer.from(row.source.utxo.publicKey, 'hex'))
		)
			throw new Error('Invalid fixed-output split witness');
		const sig = bitcoin.script.signature.decode(witness[0]);
		if (
			sig.hashType !== bitcoin.Transaction.SIGHASH_ALL ||
			!getECPair()
				.fromPublicKey(witness[1])
				.verify(
					tx.hashForWitnessV0(
						0,
						bitcoin.payments.p2pkh({ pubkey: witness[1] }).output!,
						row.source.utxo.value,
						sig.hashType
					),
					sig.signature
				)
		)
			throw new Error('Invalid fixed-output split signature');
		if (
			BigInt(row.fee) <
			BigInt(
				Math.ceil(
					tx.virtualSize() * (this.policy.preparationFeeRatePerVbyte ?? 1)
				)
			)
		)
			throw new Error('Fixed-output split feerate is insufficient');
		return tx;
	}
	private async retainSource(row: Preparation): Promise<void> {
		const current = this.wallet.listUtxos!().find(
			(u) => key(u) === key(row.source.utxo)
		);
		if (
			!current ||
			current.value !== row.source.utxo.value ||
			current.path !== row.source.utxo.path ||
			current.publicKey !== row.source.utxo.publicKey
		)
			throw new Error(
				'Fixed-output preparation source is no longer unspent and owned'
			);
		if (current.height <= 0)
			throw new FixedOutputFeePreparationPendingError(current.tx_hash);
		await this.freeze(
			row.source.utxo.tx_hash,
			row.source.utxo.tx_pos,
			this.prefix + ':source:' + row.id
		);
	}
	private async resume(row: Preparation): Promise<void> {
		const source = row.source;
		this.checkCoin(source);
		if (row.state === 'building') {
			await this.retainSource(row);
			const script = bitcoin.address.toOutputScript(row.address, this.network);
			this.owner(script);
			const estimate = new bitcoin.Transaction();
			estimate.version = 2;
			estimate.addInput(
				bitcoin.Transaction.fromHex(source.previous).getHash(),
				source.utxo.tx_pos,
				0xffffffff
			);
			for (let i = 0; i < row.count; i++)
				estimate.addOutput(script, row.amount);
			estimate.addOutput(script, 330);
			estimate.setWitness(0, [
				Buffer.alloc(73),
				Buffer.from(source.utxo.publicKey, 'hex')
			]);
			let fee = Math.ceil(
				estimate.virtualSize() * (this.policy.preparationFeeRatePerVbyte ?? 1)
			);
			const change = source.utxo.value - row.amount * row.count - fee;
			if (change < 0)
				throw new Error('Fixed-output split source cannot cover its outputs');
			if (change < 330) fee += change;
			const psbt = new bitcoin.Psbt({ network: this.network });
			psbt.setVersion(2);
			psbt.addInput({
				hash: source.utxo.tx_hash,
				index: source.utxo.tx_pos,
				sequence: 0xffffffff,
				witnessUtxo: bitcoin.Transaction.fromHex(source.previous).outs[
					source.utxo.tx_pos
				],
				// This is an explicit local-wallet PSBT. The exact public key and path
				// authorize signing; no external signer fingerprint is being asserted.
				bip32Derivation: [
					{
						masterFingerprint: Buffer.alloc(4),
						path: source.utxo.path,
						pubkey: Buffer.from(source.utxo.publicKey, 'hex')
					}
				]
			});
			for (let i = 0; i < row.count; i++)
				psbt.addOutput({ script, value: row.amount });
			if (change >= 330) psbt.addOutput({ script, value: change });
			const prepared = {
				...row,
				state: 'unsigned' as const,
				unsigned: psbt.toBase64(),
				fee: String(fee)
			};
			this.validateUnsigned(prepared);
			this.updatePreparation(row.id, prepared);
			row = prepared;
		}
		if (row.state === 'unsigned') {
			await this.retainSource(row);
			this.validateUnsigned(row);
			let signed = this.unsavedSigned.get(row.id);
			if (!signed) {
				const result = this.wallet.signPsbtWithOurKey!(row.unsigned!);
				if (result.isErr())
					throw new Error('Fixed-output split signing failed');
				const imported = this.wallet.importSignedPsbt!(
					(result as { isErr(): boolean; isOk(): boolean; value: string })
						.value,
					row.unsigned!
				);
				if (imported.isErr())
					throw new Error('Fixed-output split signature validation failed');
				signed = (
					imported as {
						isErr(): boolean;
						isOk(): boolean;
						value: { txHex: string };
					}
				).value.txHex;
				this.validateSigned(row, signed);
				this.unsavedSigned.set(row.id, signed);
			}
			this.updatePreparation(row.id, { state: 'signed', signed });
			this.unsavedSigned.delete(row.id);
			row = this.journal.preparations.find((p) => p.id === row.id)!;
		}
		const tx = this.validateSigned(row, row.signed!);
		const visible = this.wallet.listUtxos!().some(
			(c) => c.tx_hash === tx.getId()
		);
		const sourceLive = this.wallet.listUtxos!().some(
			(c) => key(c) === key(source.utxo)
		);
		if (!visible && (row.state !== 'published' || sourceLive)) {
			if (row.observed) {
				this.updatePreparation(row.id, { observed: false });
				row.observed = false;
			}
			const result = await this.wallet.electrum.broadcastTransaction({
				rawTx: row.signed!
			});
			if (result.isErr())
				throw new Error(
					'Fixed-output split publication failed; exact candidate retained'
				);
		}
		const observed =
			visible || this.wallet.listUtxos!().some((c) => c.tx_hash === tx.getId());
		if (row.state !== 'published' || (observed && !row.observed))
			this.updatePreparation(row.id, {
				state: 'published',
				observed: observed || row.observed
			});
	}

	async select(
		targetFeeSats: bigint,
		feeratePerKw: number,
		opts: IFeeBumpSelectionOpts
	): Promise<{
		inputs: ISpliceWalletInput[];
		changeScript: Buffer;
		maxFeeSatoshis: bigint;
	}> {
		return this.wallet.withSendLock!(() =>
			this.selectLocked(targetFeeSats, feeratePerKw, opts)
		);
	}
	private async clearOrphanSourceFreezes(): Promise<void> {
		const prefix = this.prefix + ':source:';
		for (const coin of this.wallet.listFrozenUtxos!()) {
			if (!coin.freezeTag?.startsWith(prefix)) continue;
			const id = coin.freezeTag.slice(prefix.length);
			const row = this.journal.preparations.find((p) => p.id === id);
			if (row) {
				if (key(row.source.utxo) !== `${coin.tx_hash}:${coin.tx_pos}`)
					throw new Error('Fixed-output source freeze identity mismatch');
				continue;
			}
			// No journal exists, so no unsigned signing intent or published split
			// could have followed this reservation. Release only our exact tag.
			const result = await this.wallet.unfreezeUtxoIfTagged!({
				txid: coin.tx_hash,
				index: coin.tx_pos,
				tag: coin.freezeTag
			});
			if (result.isErr())
				throw new Error('Fixed-output orphan reservation release failed');
		}
	}
	private async selectLocked(
		targetFeeSats: bigint,
		feeratePerKw: number,
		opts: IFeeBumpSelectionOpts
	): Promise<{
		inputs: ISpliceWalletInput[];
		changeScript: Buffer;
		maxFeeSatoshis: bigint;
	}> {
		const actionId = opts.feeActionId;
		if (
			typeof actionId !== 'string' ||
			!actionId ||
			actionId.length > 512 ||
			targetFeeSats < 0n ||
			!Number.isSafeInteger(feeratePerKw) ||
			feeratePerKw <= 0
		)
			throw new Error('Invalid fixed-output fee action');
		if (
			`${this.wallet.network ?? 'bitcoin'}:${
				this.policy.walletId ?? this.wallet.id
			}` !== this.identity
		)
			throw new Error('Fixed-output wallet identity changed');
		if (opts.maxFeeSatoshis !== undefined && !positive(opts.maxFeeSatoshis))
			throw new Error('Invalid fixed-output caller fee cap');
		const requestedCap =
			opts.maxFeeSatoshis !== undefined &&
			opts.maxFeeSatoshis < this.policy.maxFeeSatoshis
				? opts.maxFeeSatoshis
				: this.policy.maxFeeSatoshis;
		const id = bitcoin.crypto.sha256(Buffer.from(actionId)).toString('hex');
		if (
			(opts.excludeTxids ?? []).some((value) => !/^[a-f0-9]{64}$/i.test(value))
		)
			throw new Error('Invalid excluded fee transaction');
		this.reload();
		await this.completeRetirements();
		if (this.journal.actions[id]?.retired)
			throw new Error('Fixed-output fee action is retired');
		await this.clearOrphanSourceFreezes();
		if (!Object.prototype.hasOwnProperty.call(this.journal.actions, id)) {
			const next = copy(this.journal);
			next.actions[id] = {
				cap: requestedCap.toString(),
				feeActionId: actionId,
				inputs: []
			};
			this.save(next);
		}
		await this.refresh();
		for (const row of this.journal.preparations) await this.resume(copy(row));
		await this.refresh();
		const excluded = new Set(
			(opts.excludeTxids ?? []).map((s) => s.toLowerCase())
		);
		const action = this.journal.actions[id];
		const cap =
			BigInt(action.cap) < requestedCap ? BigInt(action.cap) : requestedCap;
		const replacementKeys = new Set(
			(opts.replacementInputs ?? []).map(
				(i) => `${i.txid.toLowerCase()}:${i.vout}`
			)
		);
		const live = this.wallet.listUtxos!();
		for (const coin of action.inputs) {
			this.checkCoin(coin);
			if (
				excluded.has(coin.utxo.tx_hash) ||
				(!live.some((u) => key(u) === key(coin.utxo)) &&
					!replacementKeys.has(key(coin.utxo)))
			)
				throw new Error('Reserved fixed-output fee input is unavailable');
		}
		for (const wanted of replacementKeys)
			if (!action.inputs.some((coin) => key(coin.utxo) === wanted))
				throw new Error('Unreserved fixed-output replacement input');
		const selected = [...action.inputs],
			reserved = this.reservedOutpoints();
		let sum = selected.reduce((total, c) => total + BigInt(c.utxo.value), 0n);
		const target = (count: number): bigint =>
			targetFeeSats + spliceFeeSats(count * P2WPKH_INPUT_WEIGHT, feeratePerKw);
		const available = live
			.filter(
				(coin) =>
					!reserved.has(key(coin)) &&
					!excluded.has(coin.tx_hash.toLowerCase()) &&
					!this.wallet.isUtxoFrozen!(coin.tx_hash, coin.tx_pos) &&
					bitcoin.address.toOutputScript(coin.address, this.network).equals(
						bitcoin.payments.p2wpkh({
							pubkey: Buffer.from(coin.publicKey, 'hex')
						}).output!
					)
			)
			.sort((a, b) => a.value - b.value);
		const candidates = available.filter(
			(coin) => !(opts.confirmedOnly || replacementKeys.size) || coin.height > 0
		);
		const remaining = [...candidates];
		while (
			remaining.length &&
			(sum < target(selected.length) || !selected.length)
		) {
			const adequate = remaining.findIndex(
				(coin) =>
					sum + BigInt(coin.value) >= target(selected.length + 1) &&
					sum + BigInt(coin.value) <= cap
			);
			const index =
				adequate >= 0
					? adequate
					: remaining
							.map((coin, position) => ({ coin, index: position }))
							.reverse()
							.find(({ coin }) => sum + BigInt(coin.value) <= cap)?.index;
			if (index === undefined) break;
			const coin = remaining.splice(index, 1)[0];
			const previous = (
				await this.host.previousTransactions([coin.tx_hash])
			).get(coin.tx_hash);
			if (!previous) throw new Error('Missing fixed-output fee prevout');
			const entry = { utxo: { ...coin }, previous };
			this.checkCoin(entry);
			selected.push(entry);
			sum += BigInt(coin.value);
		}
		if (sum < target(selected.length) || !selected.length) {
			const retained = action.inputs.reduce(
				(total, c) => total + BigInt(c.utxo.value),
				0n
			);
			const needed = target(action.inputs.length + 1) - retained;
			const amount = needed > 330n ? needed : 330n;
			if (retained + amount > cap)
				throw new Error('Fixed-output action fee cap exhausted');
			const unseen = this.journal.preparations.find(
				(p) => p.signed && !p.observed
			);
			if (unseen)
				throw new FixedOutputFeePreparationPendingError(
					bitcoin.Transaction.fromHex(unseen.signed!).getId()
				);
			const pending = this.journal.preparations.find(
				(p) =>
					p.signed &&
					live.some(
						(u) =>
							u.tx_hash === bitcoin.Transaction.fromHex(p.signed!).getId() &&
							u.height <= 0
					)
			);
			if (pending && (opts.confirmedOnly || replacementKeys.size))
				throw new FixedOutputFeePreparationPendingError(
					bitcoin.Transaction.fromHex(pending.signed!).getId()
				);
			const sources = candidates
				.filter(
					(coin) =>
						coin.height > 0 &&
						BigInt(coin.value) >= amount + this.policy.maxPreparationFeeSatoshis
				)
				.sort((a, b) => b.value - a.value);
			const source = sources[0];
			if (!source) {
				// The only fee coin may have just funded anchor CPFP. Its owned
				// change can prepare the HTLC fee after confirmation, so defer
				// only when that exact eligible source is authenticated.
				const waiting = available.find(
					(coin) =>
						coin.height <= 0 &&
						BigInt(coin.value) >= amount + this.policy.maxPreparationFeeSatoshis
				);
				if (waiting) {
					const previous = (
						await this.host.previousTransactions([waiting.tx_hash])
					).get(waiting.tx_hash);
					if (!previous)
						throw new Error('Missing unconfirmed fixed-output fee prevout');
					this.checkCoin({ utxo: waiting, previous });
					throw new FixedOutputFeePreparationPendingError(waiting.tx_hash);
				}
				throw new Error(
					'No confirmed ordinary Bitcoin coin can prepare fixed-output fees'
				);
			}
			const previous = (
				await this.host.previousTransactions([source.tx_hash])
			).get(source.tx_hash)!;
			const count = Math.min(
				this.policy.feeCoinCount ?? 4,
				Number(
					(BigInt(source.value) - this.policy.maxPreparationFeeSatoshis) /
						amount
				)
			);
			const addressResult = await this.wallet.getChangeAddress!(
				EAddressType.p2wpkh
			);
			if (addressResult.isErr())
				throw new Error('Fixed-output fee address unavailable');
			const address = (
				addressResult as {
					isErr(): boolean;
					isOk(): boolean;
					value: { address: string };
				}
			).value.address;
			this.owner(bitcoin.address.toOutputScript(address, this.network));
			const next = copy(this.journal),
				row: Preparation = {
					id: String(next.preparations.length),
					state: 'building',
					source: { utxo: { ...source }, previous },
					address,
					amount: Number(amount),
					count,
					fee: this.policy.maxPreparationFeeSatoshis.toString()
				};
			this.checkCoin(row.source);
			next.preparations.push(row);
			this.assertBudget(next);
			await this.freeze(
				source.tx_hash,
				source.tx_pos,
				this.prefix + ':source:' + row.id
			);
			this.save(next);
			await this.resume(row);
			await this.refresh();
			throw new FixedOutputFeePreparationPendingError(
				bitcoin.Transaction.fromHex(
					this.journal.preparations.find((p) => p.id === row.id)!.signed!
				).getId()
			);
		}
		if (sum > cap) throw new Error('Fixed-output action fee cap exhausted');
		const next = copy(this.journal);
		next.actions[id].inputs = selected;
		this.save(next);
		const inputs: ISpliceWalletInput[] = [];
		for (const coin of selected) {
			await this.host.pledge(
				coin.utxo.tx_hash,
				coin.utxo.tx_pos,
				this.prefix + ':action:' + id
			);
			const current = live.find((u) => key(u) === key(coin.utxo));
			inputs.push(
				this.host.input(
					{ ...coin.utxo, height: current?.height ?? 0 },
					coin.previous
				)
			);
		}
		return {
			inputs,
			changeScript: Buffer.alloc(0),
			maxFeeSatoshis: cap
		};
	}
}
