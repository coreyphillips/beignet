import * as bitcoin from 'bitcoinjs-lib';
import type { IWalletLike, ISpliceUtxo } from './wallet-funding-provider';
import type { IFeeBumpSelectionOpts } from '../node/types';
import type { ISpliceWalletInput } from '../channel/channel';
import type { ILedgerKeyValueStorage } from '../storage/durable-ledger';
import { EAddressType } from '../../types';
import { getECPair } from '../../utils/ecc-apis';
import {
	FIXED_OUTPUT_FEE_TIMING,
	fixedOutputFeeWaitMakesDeadline,
	parseFixedOutputHtlcFeeActionId
} from '../chain/types';
import { P2WPKH_INPUT_WEIGHT, spliceFeeSats } from '../channel/splice-weight';

/**
 * Explicit wallet-wide fee limits. They govern new actions and new splits
 * only: whatever the journal already holds keeps the terms it was recorded
 * with and can always be completed, so a policy lowered below it never stops
 * the pool from being built. Retirement charges an action its whole cap
 * unless the caller names the transaction that settled it.
 */
export interface IFixedOutputFeePolicy {
	storage: ILedgerKeyValueStorage;
	/** Defaults to Wallet.id. The same wallet must use the same identity after restart. */
	walletId?: string;
	/** Maximum wallet value burned by any one HTLC action, including replacements. */
	maxFeeSatoshis: bigint;
	/**
	 * The lifetime budget: the caps of the actions still open, what retired
	 * actions were charged, and the fees of the splits, unfinished ones
	 * included. A new action or split that would pass it is refused with
	 * FixedOutputFeeBudgetExhaustedError; nothing recorded is.
	 */
	maxTotalFeeSatoshis: bigint;
	/** The most one split may pay in its own fee. A split that cannot fit it is never recorded. */
	maxPreparationFeeSatoshis: bigint;
	/** The most equal owned fee outputs one split makes, from 1 through 16. Default 4. */
	feeCoinCount?: number;
	/**
	 * The least a split pays, in sat/vByte. Default 1. A split pays the rate
	 * of the spend it is made for when that is higher, within
	 * maxPreparationFeeSatoshis, and one that does not confirm is replaced
	 * by one that pays more.
	 */
	preparationFeeRatePerVbyte?: number;
	/**
	 * The longest the pool waits for one wallet call, or for the wallet's send
	 * lock, in milliseconds, from 1 through 600000. Default 30000. Past it the
	 * selection fails with FEE_WALLET_TIMEOUT and gives up its place, so one
	 * call that never settles cannot hold back every later selection.
	 */
	walletCallTimeoutMs?: number;
}

/**
 * What a refusal asks of the caller. `wait`: nothing is wrong, try again
 * later. `operator`: it will not pass until a setting or the wallet's funds
 * change. `none`: the request itself can never be served.
 */
export type FixedOutputFeeRemedy = 'wait' | 'operator' | 'none';

export type FixedOutputFeeErrorCode =
	| 'FEE_PREPARATION_PENDING'
	| 'FEE_PREPARATION_NOT_PUBLISHED'
	| 'FEE_WALLET_TIMEOUT'
	| 'FEE_WALLET_UNAVAILABLE'
	| 'FEE_RESERVATION_REFUSED'
	| 'FEE_BUDGET_EXHAUSTED'
	| 'FEE_FUNDS_UNAVAILABLE'
	| 'FEE_ACTION_CAP_EXHAUSTED'
	| 'FEE_PREPARATION_FEE_EXCEEDS_CAP'
	| 'FEE_PREPARATION_SIGNING_FAILED'
	| 'FEE_POLICY_REFUSED'
	| 'FEE_ACTION_RETIRED'
	| 'FEE_INPUT_UNAVAILABLE';

/**
 * Every refusal of the pool that is not a fault. `code` is stable, and
 * `remedy` says whether to wait, to ask the operator, or neither. Anything
 * else the pool throws is a plain Error: an invalid argument, or a journal,
 * coin or signature that failed its own checks.
 */
export class FixedOutputFeeError extends Error {
	constructor(
		readonly code: FixedOutputFeeErrorCode,
		readonly remedy: FixedOutputFeeRemedy,
		message: string
	) {
		super(message);
		this.name = 'FixedOutputFeeError';
	}
}

/** A split is on its way: wait for the wallet to see it, or for it to confirm. */
export class FixedOutputFeePreparationPendingError extends FixedOutputFeeError {
	constructor(readonly transactionId: string) {
		super(
			'FEE_PREPARATION_PENDING',
			'wait',
			'Fixed-output fee preparation is awaiting wallet visibility or confirmation'
		);
		this.name = 'FixedOutputFeePreparationPendingError';
	}
}

/** What the lifetime fee budget stands at. */
export interface IFixedOutputFeeBudget {
	/** The policy's maxTotalFeeSatoshis. */
	totalSatoshis: bigint;
	/**
	 * What the actions still open can still spend (the cap of one that has
	 * no fee coin yet, the fee coins of one that has), and the fees of the
	 * splits not yet signed.
	 */
	reservedSatoshis: bigint;
	/** What retired actions were charged, and the fees of the splits that were signed. */
	spentSatoshis: bigint;
	/** What a new action or split may still reserve. Never below zero. */
	remainingSatoshis: bigint;
}

/**
 * A new fee action, or a new split, would pass the lifetime budget. Nothing
 * was reserved. Everything already recorded is served as before: only new
 * spending waits for a larger maxTotalFeeSatoshis.
 */
export class FixedOutputFeeBudgetExhaustedError extends FixedOutputFeeError {
	constructor(
		/** The budget as it stood when the reservation was refused. */
		readonly budget: IFixedOutputFeeBudget,
		/** What the refused reservation would have set aside. */
		readonly neededSatoshis: bigint
	) {
		super(
			'FEE_BUDGET_EXHAUSTED',
			'operator',
			'Fixed-output lifetime fee budget is used up: ' +
				`${neededSatoshis} sats are needed and ` +
				`${budget.remainingSatoshis} of ${budget.totalSatoshis} remain ` +
				`(${budget.reservedSatoshis} reserved, ${budget.spentSatoshis} spent)`
		);
		this.name = 'FixedOutputFeeBudgetExhaustedError';
	}
}

/** How a fee action ended, named by the caller when it retires the action. */
export interface IFixedOutputFeeResolution {
	/**
	 * The raw transaction that irrevocably settled the action: the one that
	 * spent its HTLC output, the caller's own or the peer's, or one that made
	 * the action's transaction impossible. The action is charged the coins of
	 * its own that this transaction spends, and every other coin goes back to
	 * the pool for another action.
	 */
	spendingTransaction?: Buffer;
	/**
	 * The output the action was opened for never came to exist and never
	 * can: its commitment was seen, and another was confirmed in its place
	 * for good. No form of the action's spend can confirm, so the action is
	 * charged nothing and every coin of it goes back to the pool. Read only
	 * when no transaction is named.
	 */
	impossible?: true;
}

/**
 * What the fee coin pool holds and can do, read without changing anything:
 * for a host that shows it, or warns before a fee cannot be paid.
 */
export interface IFixedOutputFeePoolState {
	/** A fee policy is in force and the pool can be asked for fee coins. */
	available: true;
	budget: IFixedOutputFeeBudget;
	/**
	 * The fee coins no action holds, as the wallet lists them now. `ready`
	 * are confirmed, and are what a selection with confirmedOnly can take.
	 */
	feeCoins: { ready: number; readySatoshis: bigint; unconfirmed: number };
	/** The actions still open: each holds its cap in the budget until retired. */
	actions: Array<{
		feeActionId?: string;
		capSatoshis: bigint;
		/** The fee coins the action holds, and their sum. */
		inputs: number;
		heldSatoshis: bigint;
	}>;
	/** The splits on their way: recorded and not yet closed. */
	splits: Array<{
		state: 'unsigned' | 'signed' | 'published';
		transactionId?: string;
		feeSatoshis: bigint;
		feeCoins: number;
		feeCoinSatoshis: bigint;
	}>;
	/**
	 * Whether a split for a fee coin of `forFeeSatoshis` could be made now,
	 * were one needed: the wallet lists a confirmed ordinary coin of at least
	 * `neededSatoshis`, and the budget has room for the split's fee. No split
	 * is made by asking. `reason` is the refusal a selection would end with.
	 */
	preparation: {
		possible: boolean;
		forFeeSatoshis: bigint;
		neededSatoshis: bigint;
		largestConfirmedSatoshis: bigint;
		reason?: 'FEE_FUNDS_UNAVAILABLE' | 'FEE_BUDGET_EXHAUSTED';
	};
	/**
	 * The refusal the most recent refused selection of this provider ended
	 * with, and when, in milliseconds since the epoch. It is not cleared by
	 * a later selection that was served; compare `at`.
	 */
	lastRefusal?: {
		code: FixedOutputFeeErrorCode;
		remedy: FixedOutputFeeRemedy;
		at: number;
		/** The height by which the spend that was refused has to confirm, when it has one. */
		deadlineHeight?: number;
	};
}

/**
 * A fee policy was supplied and the wallet refused it, so there is no pool:
 * no fee coin can be prepared or spent until a policy the wallet takes is
 * supplied.
 */
export interface IFixedOutputFeePoolUnavailable {
	available: false;
	/** FEE_POLICY_REFUSED, for the operator, with the wallet's reason. */
	error: FixedOutputFeeError;
}

/** What a provider that was given a fee policy says of its fee coin pool. */
export type IFixedOutputFeeStatus =
	| IFixedOutputFeePoolState
	| IFixedOutputFeePoolUnavailable;

/**
 * The refusal of a provider whose fee policy the wallet refused, and
 * undefined for every other provider: one with a pool, one that was given
 * no policy, and one from before the read existed.
 */
export function fixedOutputFeePolicyRefusal(
	provider:
		| { getFixedOutputFeeStatus?(): IFixedOutputFeeStatus | undefined }
		| null
		| undefined
): FixedOutputFeeError | undefined {
	try {
		const status = provider?.getFixedOutputFeeStatus?.();
		return status && !status.available ? status.error : undefined;
	} catch {
		return undefined;
	}
}

type Coin = { utxo: ISpliceUtxo; previous: string };
type Preparation = {
	id: string;
	/** `building` is read from an older journal only, and is abandoned. */
	state: 'building' | 'unsigned' | 'signed' | 'published';
	source: Coin;
	address: string;
	amount: number;
	count: number;
	fee: string;
	/** The most this split may pay, as reserved when it was recorded. */
	cap?: string;
	/** The feerate it was recorded at, in sat/vByte. */
	rate?: number;
	/** The wallet knows the transaction, and listed none of its fee coins. */
	observed?: boolean;
	unsigned?: string;
	signed?: string;
	/** The id of the signed split, so its fee coins are reserved without parsing it. */
	txid?: string;
	/** The chain height it went out at, or was last replaced at, when the caller named one. */
	at?: number;
	/** How many times it was replaced by one that pays more. */
	raises?: number;
	/** The wallet has listed a fee coin of it. */
	listed?: true;
	/** The splits it replaced: any of them may still be the one a block takes. */
	prior?: Array<{ txid: string; signed: string; fee: string }>;
	/**
	 * Its replacement, signed, recorded before it is sent. Until it is
	 * settled, the journal's charges hold what it pays over the split it was
	 * recorded for. It takes the split's place once it is out, its charge
	 * then added to what was spent, and is dropped with its charge once it
	 * is refused.
	 */
	replacement?: Preparation;
};
type Action = {
	cap: string;
	inputs: Coin[];
	feeActionId?: string;
	retired?: boolean;
	/** What the action is charged once retired, in place of its cap. */
	paid?: string;
	/** Read from an older journal only: such an action is dropped at the next write. */
	released?: boolean;
	/** Coins the action held and the wallet stopped listing, for the charge at retirement. */
	gone?: { outpoint: string; value: number }[];
	/** The coins a named resolution did not spend: they go back to the pool. */
	kept?: string[];
	/**
	 * Where coins of the action were before a split replacement, or a block
	 * that took the split a replacement replaced, moved them, each with the
	 * outpoint the coin has now.
	 */
	moved?: Record<string, string>;
};
type Journal = {
	version: 1;
	identity: string;
	actions: Record<string, Action>;
	preparations: Preparation[];
	/** The fee coins the pool's own splits made that no action holds. */
	coins?: Coin[];
	/**
	 * The splits whose fee coins the wallet listed before their transaction
	 * confirmed: closed, and kept here so that one that does not confirm can
	 * be replaced by one that pays more. One leaves when the wallet lists a
	 * coin of it as confirmed, or when nothing can follow it any more.
	 */
	unconfirmed?: Preparation[];
	/** What the splits and actions no longer listed were charged. */
	spent?: string;
	/** The number of the next split, so a closed split's source tag is never used twice. */
	next?: number;
	/** The actions retired most recently, so a late selection for one is still refused. */
	retiredIds?: string[];
	/**
	 * Each split replacement recorded and not yet settled, with the split it
	 * replaces and what it pays over that split: spent, for the budget, until
	 * it is settled. A release that does not know these keeps them when it
	 * drops the row of the split; they are then settled by what the wallet
	 * lists and the server knows.
	 */
	charges?: Array<{ txid: string; split: string; over: string }>;
};
type View = {
	encoded: string | null;
	journal: Journal;
	reserved: Set<string>;
	tags: Map<string, string>;
};
interface Host {
	previousTransactions(ids: readonly string[]): Promise<Map<string, string>>;
	/**
	 * For each transaction the wallet's server answered about, whether it
	 * knows it. One it gave no answer for is left out.
	 */
	knownTransactions?(ids: readonly string[]): Promise<Map<string, boolean>>;
	input(coin: ISpliceUtxo, previous: string): ISpliceWalletInput;
	pledge(txid: string, index: number, tag: string): Promise<void>;
	release(txid: string, index: number, tag: string): Promise<void>;
}
type Selection = {
	inputs: ISpliceWalletInput[];
	changeScript: Buffer;
	maxFeeSatoshis: bigint;
};
/** How many retired actions the journal remembers by name. */
const RETIRED_IDS = 128;
const DEFAULT_WALLET_CALL_TIMEOUT_MS = 30_000;
const DUST = 330;
/** The input of a split says the split may be replaced (BIP 125). */
const SPLIT_SEQUENCE = 0xfffffffd;
/** A replacement pays at least 3/2 of the rate of the split it replaces. */
const SPLIT_RAISE_NUMERATOR = 3;
const SPLIT_RAISE_DENOMINATOR = 2;
const key = (coin: Pick<ISpliceUtxo, 'tx_hash' | 'tx_pos'>): string =>
	`${coin.tx_hash.toLowerCase()}:${coin.tx_pos}`;
const copy = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;
const positive = (value: bigint): boolean =>
	typeof value === 'bigint' &&
	value > 0n &&
	value <= BigInt(Number.MAX_SAFE_INTEGER);
const timedOut = (error: unknown): boolean =>
	error instanceof FixedOutputFeeError && error.code === 'FEE_WALLET_TIMEOUT';

/**
 * A bounded, wallet-scoped fee coin pool with a durable journal. Caller holds
 * the provider operation lock.
 *
 * The pool spends only fee coins its own splits made. A split takes one
 * confirmed ordinary coin, pays the fee coins and the change to the wallet,
 * and is computed and checked before anything is recorded. From the moment
 * a split is signed its fee coins are reserved, and once the wallet lists
 * them they are frozen, until an action takes one or the wallet stops
 * listing it. One split that cannot go on never holds back a selection
 * that other fee coins can serve.
 */
export class FixedOutputFeePool {
	private readonly identity: string;
	private readonly storageKey: string;
	private readonly prefix: string;
	private readonly coinTag: string;
	private readonly network: bitcoin.Network;
	private readonly timeoutMs: number;
	private journal: Journal;
	private encoded: string | null;
	/** The stored journal as last parsed, with what it reserves. */
	private view?: View;
	/** A failed durable write keeps the exact signed bytes for the next in-process retry. */
	private unsavedSigned = new Map<string, string>();
	private lastRefusal?: IFixedOutputFeePoolState['lastRefusal'];

	constructor(
		private readonly wallet: IWalletLike,
		private readonly policy: IFixedOutputFeePolicy,
		private readonly host: Host
	) {
		this.policy = { ...policy };
		const identity = policy.walletId ?? wallet.id;
		const timeout =
			policy.walletCallTimeoutMs ?? DEFAULT_WALLET_CALL_TIMEOUT_MS;
		if (
			!identity ||
			identity.length > 256 ||
			!positive(policy.maxFeeSatoshis) ||
			!positive(policy.maxTotalFeeSatoshis) ||
			!positive(policy.maxPreparationFeeSatoshis) ||
			!Number.isInteger(policy.feeCoinCount ?? 4) ||
			(policy.feeCoinCount ?? 4) < 1 ||
			(policy.feeCoinCount ?? 4) > 16 ||
			!Number.isFinite(policy.preparationFeeRatePerVbyte ?? 1) ||
			(policy.preparationFeeRatePerVbyte ?? 1) < 1 ||
			(policy.preparationFeeRatePerVbyte ?? 1) > 10000 ||
			!Number.isInteger(timeout) ||
			timeout < 1 ||
			timeout > 600_000 ||
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
		this.timeoutMs = timeout;
		this.identity = `${wallet.network ?? 'bitcoin'}:${identity}`;
		this.prefix =
			'fixed-output-fees:' +
			bitcoin.crypto.sha256(Buffer.from(this.identity)).toString('hex');
		this.coinTag = this.prefix + ':coin';
		this.storageKey = this.prefix + ':journal';
		this.network =
			wallet.network === 'regtest'
				? bitcoin.networks.regtest
				: wallet.network === 'bitcoin' || !wallet.network
				? bitcoin.networks.bitcoin
				: bitcoin.networks.testnet;
		// Only that the journal is whole. What it holds is not measured against
		// the policy given now: that would let a lowered setting stop the
		// wallet from finishing what it already began.
		const view = this.latest();
		this.encoded = view.encoded;
		this.journal = view.journal;
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
			!Array.isArray(data.preparations) ||
			(data.coins !== undefined && !Array.isArray(data.coins)) ||
			(data.unconfirmed !== undefined && !Array.isArray(data.unconfirmed)) ||
			(data.retiredIds !== undefined && !Array.isArray(data.retiredIds)) ||
			(data.charges !== undefined && !Array.isArray(data.charges))
		)
			throw new Error('Invalid fixed-output fee journal');
		return data;
	}
	/**
	 * Throw unless the journal is whole. Nothing here reads the policy: an
	 * action or a split keeps the cap it was recorded with.
	 */
	private assertJournal(data: Journal): void {
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
				!Array.isArray(action.inputs) ||
				(action.paid !== undefined &&
					(BigInt(action.paid) < 0n || BigInt(action.paid) > cap))
			)
				throw new Error('Invalid fixed-output action reservation');
		}
		for (const preparation of data.preparations) {
			const fee = BigInt(preparation.fee);
			if (
				fee < 0n ||
				(preparation.cap !== undefined && fee > BigInt(preparation.cap))
			)
				throw new Error('Invalid fixed-output preparation reservation');
		}
		if (
			(data.spent !== undefined && BigInt(data.spent) < 0n) ||
			(data.charges ?? []).some((charge) => BigInt(charge.over) < 0n)
		)
			throw new Error('Invalid fixed-output fee charge');
	}
	/** What a journal charges the lifetime budget, by what it is charged for. */
	/**
	 * What an open action can still spend, which is what it holds against
	 * the budget: its cap until it has fee coins, and from then on the coins
	 * it holds with those it let go of (an earlier form of its spend may
	 * still be the one a block takes), never more than its cap.
	 */
	private held(action: Action): bigint {
		const cap = BigInt(action.cap);
		if (!action.inputs.length) return cap;
		let sum = 0n;
		for (const coin of action.inputs) sum += BigInt(coin.utxo.value);
		for (const coin of action.gone ?? []) sum += BigInt(coin.value);
		return sum < cap ? sum : cap;
	}
	private usage(data: Journal): { reserved: bigint; spent: bigint } {
		let reserved = 0n,
			spent = BigInt(data.spent ?? '0');
		for (const action of Object.values(data.actions)) {
			// A retired action is charged what its retirement recorded. One
			// retired before that was recorded is charged its whole cap.
			if (action.retired) spent += BigInt(action.paid ?? action.cap);
			else reserved += this.held(action);
		}
		for (const preparation of data.preparations) {
			// A signed split has its exact fee and may be on the wire.
			if (preparation.state === 'signed' || preparation.state === 'published')
				spent += BigInt(preparation.fee);
			else reserved += BigInt(preparation.fee);
		}
		// So may a split replacement recorded and not yet settled.
		for (const charge of data.charges ?? []) spent += BigInt(charge.over);
		return { reserved, spent };
	}
	private budgetOf(data: Journal): IFixedOutputFeeBudget {
		const { reserved, spent } = this.usage(data);
		const total = this.policy.maxTotalFeeSatoshis;
		const remaining = total - reserved - spent;
		return {
			totalSatoshis: total,
			reservedSatoshis: reserved,
			spentSatoshis: spent,
			remainingSatoshis: remaining > 0n ? remaining : 0n
		};
	}
	/** The lifetime budget as the stored journal has it. */
	budget(): IFixedOutputFeeBudget {
		return this.budgetOf(this.latest().journal);
	}
	/** Throw unless a NEW reservation of `needed` fits the lifetime budget. */
	private assertRoom(needed: bigint): void {
		const { reserved, spent } = this.usage(this.journal);
		if (reserved + spent + needed > this.policy.maxTotalFeeSatoshis)
			throw new FixedOutputFeeBudgetExhaustedError(
				this.budgetOf(this.journal),
				needed
			);
	}
	private txidOf(row: Preparation): string | undefined {
		return (
			row.txid ??
			(row.signed ? bitcoin.Transaction.fromHex(row.signed).getId() : undefined)
		);
	}
	private viewOf(encoded: string | null, journal: Journal): View {
		const reserved = new Set<string>(),
			tags = new Map<string, string>();
		for (const [id, action] of Object.entries(journal.actions)) {
			if (action.released) continue;
			for (const coin of action.inputs) {
				reserved.add(key(coin.utxo));
				tags.set(key(coin.utxo), this.prefix + ':action:' + id);
			}
		}
		for (const row of journal.preparations) {
			reserved.add(key(row.source.utxo));
			// The fee coins of a split that has a signature, whether or not
			// the wallet lists them yet.
			const txid = this.txidOf(row);
			if (txid)
				for (let i = 0; i < row.count; i++) reserved.add(`${txid}:${i}`);
		}
		for (const coin of journal.coins ?? []) reserved.add(key(coin.utxo));
		return { encoded, journal, reserved, tags };
	}
	/**
	 * The stored journal and what it reserves. One read of the stored string;
	 * it is parsed again only when that string has changed.
	 */
	private latest(): View {
		const encoded = this.policy.storage.loadMetadata(this.storageKey);
		if (!this.view || this.view.encoded !== encoded) {
			const journal = this.decode(encoded);
			this.assertJournal(journal);
			this.view = this.viewOf(encoded, journal);
		}
		return this.view;
	}
	private save(next: Journal): void {
		this.assertJournal(next);
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
		this.view = this.viewOf(encoded, this.journal);
	}
	private updatePreparation(id: string, update: Partial<Preparation>): void {
		const next = copy(this.journal),
			row = next.preparations.find((p) => p.id === id);
		if (!row) throw new Error('Missing fixed-output preparation');
		Object.assign(row, update);
		this.save(next);
	}
	isReserved(txid: string, index: number): boolean {
		return this.latest().reserved.has(`${txid.toLowerCase()}:${index}`);
	}
	/**
	 * Every outpoint the pool holds: the coins of its open actions, the
	 * source and the fee coins of each split, and the fee coins no action
	 * has taken yet. An ordinary selection leaves all of them alone.
	 */
	reservedOutpoints(): Set<string> {
		return new Set(this.latest().reserved);
	}
	/** The freeze tag of the action that holds this coin, if one does. */
	reservationTag(txid: string, index: number): string | undefined {
		return this.latest().tags.get(`${txid.toLowerCase()}:${index}`);
	}
	ownsFreeze(txid: string, index: number, tag?: string): boolean {
		return tag !== undefined && this.reservationTag(txid, index) === tag;
	}
	/** Enumerate only canonical native HTLC identities authenticated by the journal key. */
	actionIds(channelId: Buffer): readonly string[] {
		if (!Buffer.isBuffer(channelId) || channelId.length !== 32)
			throw new Error('Invalid fixed-output channel identity');
		return Object.entries(this.latest().journal.actions).flatMap(
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
		const view = this.latest();
		if (view.encoded !== this.encoded) {
			this.journal = view.journal;
			this.encoded = view.encoded;
		}
	}

	private timeout(what: string): FixedOutputFeeError {
		return new FixedOutputFeeError(
			'FEE_WALLET_TIMEOUT',
			'wait',
			`The wallet did not answer ${what} within ${this.timeoutMs} ms. ` +
				'The fixed-output fee selection was given up; try again'
		);
	}
	/**
	 * One wallet call, waited for no longer than the bound. Past it the
	 * selection throws here and runs no further, so whatever the call
	 * answers later reaches nothing: no journal write follows it.
	 */
	private bounded<T>(what: string, call: () => Promise<T>): Promise<T> {
		return new Promise<T>((resolve, reject) => {
			const timer = setTimeout(
				() => reject(this.timeout(what)),
				this.timeoutMs
			);
			let pending: Promise<T>;
			try {
				pending = Promise.resolve(call());
			} catch (error) {
				clearTimeout(timer);
				reject(error);
				return;
			}
			pending.then(
				(value) => {
					clearTimeout(timer);
					resolve(value);
				},
				(error) => {
					clearTimeout(timer);
					reject(error);
				}
			);
		});
	}
	/**
	 * Run under the wallet's send lock. The wait for the lock is bounded
	 * too, and a lock that is granted after the bound has passed runs
	 * nothing.
	 */
	private locked<T>(fn: () => Promise<T>): Promise<T> {
		return new Promise<T>((resolve, reject) => {
			let started = false,
				abandoned = false;
			const timer = setTimeout(() => {
				if (started) return;
				abandoned = true;
				reject(this.timeout('for its send lock'));
			}, this.timeoutMs);
			const settle = (deliver: () => void): void => {
				clearTimeout(timer);
				if (!abandoned) deliver();
			};
			let held: Promise<T | undefined>;
			try {
				held = this.wallet.withSendLock!(async () => {
					if (abandoned) return undefined;
					started = true;
					clearTimeout(timer);
					return fn();
				});
			} catch (error) {
				settle(() => reject(error));
				return;
			}
			held.then(
				(value) => settle(() => resolve(value as T)),
				(error) => settle(() => reject(error))
			);
		});
	}
	private async refresh(): Promise<void> {
		const result = await this.bounded('a refresh', () =>
			this.wallet.refreshWallet!({})
		);
		if (result.isErr())
			throw new FixedOutputFeeError(
				'FEE_WALLET_UNAVAILABLE',
				'wait',
				'Fixed-output fee wallet refresh failed'
			);
	}
	private async freeze(txid: string, vout: number, tag: string): Promise<void> {
		const result = await this.bounded('a freeze', () =>
			this.wallet.freezeUtxoIfUnfrozen!({ txid, index: vout, tag })
		);
		if (
			result.isErr() ||
			!this.wallet.listFrozenUtxos!().some(
				(coin) =>
					coin.tx_hash === txid &&
					coin.tx_pos === vout &&
					coin.freezeTag === tag
			)
		)
			throw new FixedOutputFeeError(
				'FEE_RESERVATION_REFUSED',
				'wait',
				'Fixed-output fee reservation belongs to another owner or was refused'
			);
	}
	/** Release our own tag on a coin, and nothing another owner holds. */
	private async unfreeze(
		txid: string,
		vout: number,
		tag: string
	): Promise<void> {
		const result = await this.bounded('a release', () =>
			this.wallet.unfreezeUtxoIfTagged!({ txid, index: vout, tag })
		);
		if (result.isErr())
			throw new FixedOutputFeeError(
				'FEE_WALLET_UNAVAILABLE',
				'wait',
				'Fixed-output reservation release failed'
			);
	}
	/** Whether the wallet's server knows a transaction. Undefined when it cannot say. */
	private async known(txid: string): Promise<boolean | undefined> {
		try {
			if (this.host.knownTransactions)
				return (
					await this.bounded('a transaction lookup', () =>
						this.host.knownTransactions!([txid])
					)
				).get(txid);
			return (
				await this.bounded('a transaction lookup', () =>
					this.host.previousTransactions([txid])
				)
			).has(txid);
		} catch (error) {
			if (timedOut(error)) throw error;
			return undefined;
		}
	}
	private async previous(txid: string): Promise<string> {
		let found: string | undefined;
		try {
			found = (
				await this.bounded('a transaction lookup', () =>
					this.host.previousTransactions([txid])
				)
			).get(txid);
		} catch (error) {
			if (timedOut(error)) throw error;
			found = undefined;
		}
		if (!found)
			throw new FixedOutputFeeError(
				'FEE_WALLET_UNAVAILABLE',
				'wait',
				'Missing fixed-output fee prevout'
			);
		return found;
	}

	private isRetired(id: string): boolean {
		return (
			this.journal.actions[id]?.retired === true ||
			(this.journal.retiredIds ?? []).includes(id)
		);
	}
	/**
	 * Finish every retirement the journal holds: release the action's own
	 * freezes, charge it, hand back the coins its resolution did not spend,
	 * and drop the action, keeping only its name among the recent ones.
	 */
	private async completeRetirements(): Promise<void> {
		const retired = Object.entries(this.journal.actions).filter(
			([, action]) => action.retired
		);
		if (!retired.length) return;
		// Those an older journal kept after their release, all in one write.
		const done = retired.filter(([, action]) => action.released);
		if (done.length) {
			const next = copy(this.journal);
			for (const [id] of done) this.dropRetired(next, id);
			this.save(next);
		}
		for (const [id, action] of retired) {
			if (action.released) continue;
			for (const coin of action.inputs)
				await this.bounded('a release', () =>
					this.host.release(
						coin.utxo.tx_hash,
						coin.utxo.tx_pos,
						this.prefix + ':action:' + id
					)
				);
			const next = copy(this.journal);
			this.dropRetired(next, id);
			this.save(next);
		}
	}
	/** Charge a retired action, hand back what its resolution kept, and forget it. */
	private dropRetired(next: Journal, id: string): void {
		const row = next.actions[id],
			kept = new Set(row.released ? [] : row.kept ?? []);
		delete next.actions[id];
		next.spent = (
			BigInt(next.spent ?? '0') + BigInt(row.paid ?? row.cap)
		).toString();
		next.retiredIds = [...(next.retiredIds ?? []), id].slice(-RETIRED_IDS);
		const held = this.viewOf(null, next).reserved;
		for (const coin of row.inputs)
			if (kept.has(key(coin.utxo)) && !held.has(key(coin.utxo)))
				(next.coins ??= []).push(coin);
	}
	/**
	 * Retire an action. The caller must have established that it is
	 * irrevocably resolved. With the transaction that settled it named, the
	 * action is charged the coins of its own that the transaction spends and
	 * the others go back to the pool. Without one the action is charged its
	 * whole cap and its coins are given up to the wallet: that a wallet still
	 * lists a coin does not show it unspent, so nothing is refunded on it.
	 * Every freeze under the pool's tags that the journal no longer owns is
	 * released then, one under the action's tag on a coin a raise let go of
	 * included.
	 */
	async retire(
		feeActionId: string,
		resolution?: IFixedOutputFeeResolution
	): Promise<void> {
		if (
			typeof feeActionId !== 'string' ||
			!feeActionId ||
			feeActionId.length > 512
		)
			throw new Error('Invalid fixed-output fee action');
		let spent: Set<string> | undefined;
		if (resolution !== undefined) {
			if (Buffer.isBuffer(resolution?.spendingTransaction)) {
				spent = new Set(
					bitcoin.Transaction.fromBuffer(
						resolution.spendingTransaction
					).ins.map(
						(input) =>
							`${Buffer.from(input.hash).reverse().toString('hex')}:${
								input.index
							}`
					)
				);
			} else if (
				resolution?.spendingTransaction === undefined &&
				resolution?.impossible === true
			) {
				// Nothing of the action can have been spent.
				spent = new Set();
			} else throw new Error('Invalid fixed-output fee resolution');
		}
		await this.locked(async () => {
			this.reload();
			const id = bitcoin.crypto
					.sha256(Buffer.from(feeActionId))
					.toString('hex'),
				action = this.journal.actions[id];
			if (action && !action.retired) {
				const next = copy(this.journal);
				// Where the unconfirmed splits say the coins were, before a
				// selection settles those splits.
				this.recordMoves(next);
				const row = next.actions[id],
					cap = BigInt(row.cap);
				row.retired = true;
				row.feeActionId = feeActionId;
				if (spent) {
					// The transaction names a coin where it was when it was made:
					// a split replacement, or a block that took the split a
					// replacement replaced, may have moved it since. It is
					// charged, and not handed back, wherever the action holds it.
					const taken = new Set(
						[...spent].map((outpoint) => this.locate(row, outpoint))
					);
					const burned = [
						...row.inputs.map((coin) => ({
							outpoint: key(coin.utxo),
							value: coin.utxo.value
						})),
						...(row.gone ?? [])
					]
						.filter((coin) => taken.has(coin.outpoint))
						.reduce((sum, coin) => sum + BigInt(coin.value), 0n);
					row.paid = (burned > cap ? cap : burned).toString();
					row.kept = row.inputs
						.map((coin) => key(coin.utxo))
						.filter((outpoint) => !taken.has(outpoint));
				} else row.paid = row.cap;
				this.save(next);
			}
			await this.completeRetirements();
			await this.releaseOrphans();
			await this.freezeCoins();
		});
	}
	/**
	 * Release every freeze under this pool's tags that the journal does not
	 * own: one left by a write that failed, by a split that was closed, or
	 * by a journal a restore did not carry.
	 */
	async releaseOrphanFreezes(): Promise<void> {
		await this.locked(async () => {
			this.reload();
			await this.completeRetirements();
			await this.releaseOrphans();
			await this.freezeCoins();
		});
	}
	/** Answers whether a freeze was released. */
	private async releaseOrphans(): Promise<boolean> {
		const owned = new Map(this.latest().tags);
		for (const row of this.journal.preparations)
			owned.set(key(row.source.utxo), this.prefix + ':source:' + row.id);
		for (const coin of this.journal.coins ?? [])
			owned.set(key(coin.utxo), this.coinTag);
		// A coin a split replacement moved is where it was again once a block
		// takes the split replaced, until a selection moves it back: the
		// freeze it had there is kept while the pool holds the coin.
		const before = new Set<string>();
		for (const row of this.journal.unconfirmed ?? []) {
			const txid = this.txidOf(row);
			for (let i = 0; txid && i < row.count; i++)
				if (owned.has(`${txid}:${i}`))
					for (const old of row.prior ?? []) before.add(`${old.txid}:${i}`);
		}
		let released = false;
		for (const coin of this.wallet.listFrozenUtxos!()) {
			const tag = coin.freezeTag;
			if (!tag?.startsWith(this.prefix + ':')) continue;
			if (owned.get(key(coin)) === tag || before.has(key(coin))) continue;
			if (tag.startsWith(this.prefix + ':action:'))
				await this.bounded('a release', () =>
					this.host.release(coin.tx_hash, coin.tx_pos, tag)
				);
			else await this.unfreeze(coin.tx_hash, coin.tx_pos, tag);
			released = true;
		}
		return released;
	}
	/**
	 * Freeze every coin the pool holds as soon as the wallet lists it: a fee
	 * coin no action holds under the pool's tag, and a coin of an open
	 * action under the action's own. A split replacement, or a block that
	 * takes the split a replacement replaced, moves coins to outpoints no
	 * freeze covers, and the wallet's own sends pass over frozen coins only.
	 */
	private async freezeCoins(): Promise<void> {
		const listed = new Set(this.wallet.listUtxos!().map((coin) => key(coin)));
		const loose = (coin: Coin): boolean =>
			listed.has(key(coin.utxo)) &&
			!this.wallet.isUtxoFrozen!(coin.utxo.tx_hash, coin.utxo.tx_pos);
		for (const coin of this.journal.coins ?? []) {
			if (!loose(coin)) continue;
			try {
				await this.freeze(coin.utxo.tx_hash, coin.utxo.tx_pos, this.coinTag);
			} catch (error) {
				if (timedOut(error)) throw error;
			}
		}
		for (const [id, action] of Object.entries(this.journal.actions)) {
			if (action.retired || action.released) continue;
			for (const coin of action.inputs) {
				if (!loose(coin)) continue;
				try {
					await this.bounded('a fee coin pledge', () =>
						this.host.pledge(
							coin.utxo.tx_hash,
							coin.utxo.tx_pos,
							this.prefix + ':action:' + id
						)
					);
				} catch (error) {
					if (timedOut(error)) throw error;
				}
			}
		}
	}
	/**
	 * Hand the free fee coins back to the wallet once no action can need
	 * them: every action is retired, and no split is unsigned or on its way.
	 * Otherwise nothing changes. A split replacement the journal records is
	 * settled first, after a refresh, as a selection settles it, but never
	 * sent again: no action needs the split to pay more. One the server
	 * cannot say of stays recorded, with its split. The journal lets go of the coins first, with the unconfirmed
	 * splits they came from, and only then is every freeze under the pool's
	 * tags released: the journal owns none any more, and one under the tag
	 * of a retired action, on a coin a raise let go of, goes with the rest.
	 * A stop in between leaves freezes the journal does not own: the release
	 * of those at the next start, or the next call of this, lets go of them,
	 * and nothing freezes them again. A later selection makes a split of its
	 * own. Answers whether a coin or a freeze was let go of.
	 */
	async releaseFreeCoins(): Promise<boolean> {
		// With no free coin and no freeze under a tag of the pool there is
		// nothing to hand back, and the wallet's send lock is not taken.
		if (
			!this.latest().journal.coins?.length &&
			!this.wallet.listFrozenUtxos!().some(
				(coin) => coin.freezeTag?.startsWith(this.prefix + ':')
			)
		)
			return false;
		return this.locked(async () => {
			this.reload();
			await this.completeRetirements();
			if (
				Object.keys(this.journal.actions).length > 0 ||
				this.journal.preparations.length > 0
			)
				return false;
			if (
				(this.journal.unconfirmed ?? []).some((row) => row.replacement) ||
				(this.journal.charges ?? []).length > 0
			) {
				await this.refresh();
				await this.settleReplacements(false);
			}
			const journal = this.journal;
			const coins = journal.coins ?? [];
			if (coins.length) {
				const from = new Set(
					coins.map((coin) => coin.utxo.tx_hash.toLowerCase())
				);
				const next = copy(journal);
				delete next.coins;
				// The rows of the splits whose coins go back go with them, a
				// recorded replacement included: no coin of the pool is left to
				// move, and its charge stays in charges until the listing or the
				// server settles it. It is never sent again.
				const rows = (next.unconfirmed ?? []).filter(
					(row) => !from.has(this.txidOf(row)!)
				);
				if (rows.length) next.unconfirmed = rows;
				else delete next.unconfirmed;
				this.save(next);
			}
			// The journal owns no freeze now: one at a place a split
			// replacement moved a coin from, and one under the tag of a
			// retired action on a coin a raise let go of, are released with
			// the rest.
			const released = await this.releaseOrphans();
			return coins.length > 0 || released;
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
			row.amount < DUST ||
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
		// Against the cap the split was recorded with, not the policy's: a
		// split the journal holds can always be completed.
		if (fee !== BigInt(row.fee) || fee < 0n || fee > BigInt(row.cap ?? row.fee))
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
		if (BigInt(row.fee) < BigInt(Math.ceil(tx.virtualSize() * (row.rate ?? 1))))
			throw new Error('Fixed-output split feerate is insufficient');
		return tx;
	}
	/**
	 * The split of `source` into `count` fee coins of `amount` at `rate`, and
	 * its exact fee. Undefined when the source cannot cover it.
	 */
	private buildSplit(
		source: Coin,
		address: string,
		amount: number,
		count: number,
		rate: number
	): { unsigned: string; fee: number } | undefined {
		const script = bitcoin.address.toOutputScript(address, this.network);
		const previous = bitcoin.Transaction.fromHex(source.previous);
		const estimate = new bitcoin.Transaction();
		estimate.version = 2;
		estimate.addInput(previous.getHash(), source.utxo.tx_pos, SPLIT_SEQUENCE);
		for (let i = 0; i < count; i++) estimate.addOutput(script, amount);
		estimate.addOutput(script, DUST);
		estimate.setWitness(0, [
			Buffer.alloc(73),
			Buffer.from(source.utxo.publicKey, 'hex')
		]);
		let fee = Math.ceil(estimate.virtualSize() * rate);
		const change = source.utxo.value - amount * count - fee;
		if (change < 0) return undefined;
		// Change too small to be an output goes to the fee, and is counted
		// in it before the fee is measured against its cap.
		if (change < DUST) fee += change;
		const psbt = new bitcoin.Psbt({ network: this.network });
		psbt.setVersion(2);
		psbt.addInput({
			hash: source.utxo.tx_hash,
			index: source.utxo.tx_pos,
			sequence: SPLIT_SEQUENCE,
			witnessUtxo: previous.outs[source.utxo.tx_pos],
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
		for (let i = 0; i < count; i++) psbt.addOutput({ script, value: amount });
		if (change >= DUST) psbt.addOutput({ script, value: change });
		return { unsigned: psbt.toBase64(), fee };
	}
	/**
	 * The largest split, of at most `most` fee coins, whose whole fee fits
	 * `cap`. Nothing is recorded or frozen before this has passed.
	 */
	private fitSplit(
		source: Coin,
		address: string,
		amount: number,
		most: number,
		rate: number,
		cap: bigint
	): { unsigned: string; fee: number; count: number } {
		let least: number | undefined;
		for (let count = most; count >= 1; count--) {
			const built = this.buildSplit(source, address, amount, count, rate);
			if (!built) continue;
			if (BigInt(built.fee) <= cap) return { ...built, count };
			least = least === undefined ? built.fee : Math.min(least, built.fee);
		}
		if (least === undefined)
			throw new FixedOutputFeeError(
				'FEE_FUNDS_UNAVAILABLE',
				'operator',
				'Fixed-output split source cannot cover its outputs'
			);
		throw new FixedOutputFeeError(
			'FEE_PREPARATION_FEE_EXCEEDS_CAP',
			'operator',
			`Fixed-output split exceeds preparation fee cap: it costs ${least} sats ` +
				`at ${rate} sat/vB and maxPreparationFeeSatoshis is ${cap}. ` +
				'Nothing was recorded'
		);
	}
	/** Drop a split that was never signed for the wire, and release its source. */
	private async abandon(row: Preparation): Promise<void> {
		const next = copy(this.journal);
		next.preparations = next.preparations.filter((p) => p.id !== row.id);
		this.save(next);
		this.unsavedSigned.delete(row.id);
		try {
			await this.unfreeze(
				row.source.utxo.tx_hash,
				row.source.utxo.tx_pos,
				this.prefix + ':source:' + row.id
			);
		} catch (error) {
			// The next call releases it as a freeze no row owns.
			if (timedOut(error)) throw error;
		}
	}
	/**
	 * Close a split that left the pool's hands: its fee stays charged, and
	 * the fee coins the wallet lists become the pool's free coins.
	 */
	private close(row: Preparation, outputs: ISpliceUtxo[]): void {
		const next = copy(this.journal);
		next.preparations = next.preparations.filter((p) => p.id !== row.id);
		next.spent = (BigInt(next.spent ?? '0') + BigInt(row.fee)).toString();
		const held = this.viewOf(null, next).reserved;
		for (const output of outputs)
			if (!held.has(key(output)))
				(next.coins ??= []).push({
					utxo: { ...output },
					previous: row.signed!
				});
		// Its coins are listed and none is confirmed: the split may still
		// have to be replaced by one that pays more.
		if (outputs.length && outputs.every((output) => output.height <= 0))
			(next.unconfirmed ??= []).push({
				...copy(row),
				state: 'published',
				listed: true
			});
		this.save(next);
	}
	/**
	 * The coins of split `from` that the pool or an action holds become the
	 * coins at the same positions of `to`. An action keeps where each of its
	 * coins was, since the node's spend may still name it there.
	 */
	private move(
		next: Journal,
		from: string,
		to: { txid: string; signed: string },
		unconfirmed: boolean
	): void {
		const moved = (coin: Coin): Coin =>
			coin.utxo.tx_hash.toLowerCase() === from
				? {
						utxo: {
							...coin.utxo,
							tx_hash: to.txid,
							...(unconfirmed ? { height: 0 } : {})
						},
						previous: to.signed
				  }
				: coin;
		if (next.coins) next.coins = next.coins.map(moved);
		for (const action of Object.values(next.actions))
			action.inputs = action.inputs.map((coin) => {
				const now = moved(coin);
				if (now === coin) return coin;
				const was = key(coin.utxo),
					is = key(now.utxo),
					map = (action.moved ??= {});
				for (const earlier of Object.keys(map))
					if (map[earlier] === was) map[earlier] = is;
				map[was] = is;
				delete map[is];
				return now;
			});
	}
	/** Whether the action holds the coin at `outpoint`, or let go of it. */
	private has(action: Action, outpoint: string): boolean {
		return (
			action.inputs.some((coin) => key(coin.utxo) === outpoint) ||
			(action.gone ?? []).some((coin) => coin.outpoint === outpoint)
		);
	}
	/**
	 * The outpoint of the action's coin that a transaction names at
	 * `named`. A spend made before a split replacement, or before a block
	 * that took the split a replacement replaced, names the coin where it
	 * was. The action's moved record says where it went, and is followed only
	 * while the action holds the coin it points to, or let go of it: a
	 * release that does not keep the record may have moved the coin since.
	 * Anything else is answered as named.
	 */
	private locate(action: Action, named: string): string {
		if (this.has(action, named)) return named;
		const recorded = action.moved?.[named];
		return recorded !== undefined && this.has(action, recorded)
			? recorded
			: named;
	}
	/**
	 * Add to the moved record of each open action what the unconfirmed
	 * splits say of the coins it holds: a coin at a position of a split that
	 * replaced others was at the same position of each of those (its prior
	 * field). A journal of a release that kept no moved record still has
	 * this while the split has not confirmed, so it is read before the split
	 * can leave. Answers whether anything was added.
	 */
	private recordMoves(journal: Journal): boolean {
		let added = false;
		for (const row of journal.unconfirmed ?? []) {
			const txid = this.txidOf(row),
				prior: Array<{ txid: string }> = row.prior ?? [];
			if (!txid || !prior.length) continue;
			for (const action of Object.values(journal.actions)) {
				if (action.retired || action.released) continue;
				for (const coin of action.inputs) {
					if (coin.utxo.tx_hash.toLowerCase() !== txid) continue;
					for (const earlier of prior) {
						const was = `${earlier.txid}:${coin.utxo.tx_pos}`;
						if (action.moved?.[was] !== undefined || this.has(action, was))
							continue;
						(action.moved ??= {})[was] = key(coin.utxo);
						added = true;
					}
				}
			}
		}
		return added;
	}
	/** The rate a split is made at for a spend asked at `feeratePerKw`. */
	private splitRate(feeratePerKw: number): number {
		return Math.min(
			10000,
			Math.max(
				this.policy.preparationFeeRatePerVbyte ?? 1,
				Math.ceil(feeratePerKw / 250)
			)
		);
	}
	/**
	 * The split at the rate wanted, or, when that does not fit the cap of a
	 * split, at the highest rate that does, never below the policy's own.
	 */
	private planSplit(
		source: Coin,
		address: string,
		amount: number,
		most: number,
		wanted: number
	): { unsigned: string; fee: number; count: number; rate: number } {
		const cap = this.policy.maxPreparationFeeSatoshis,
			least = this.policy.preparationFeeRatePerVbyte ?? 1;
		try {
			return {
				...this.fitSplit(source, address, amount, most, wanted, cap),
				rate: wanted
			};
		} catch (error) {
			if (
				!(error instanceof FixedOutputFeeError) ||
				error.code !== 'FEE_PREPARATION_FEE_EXCEEDS_CAP' ||
				wanted <= least
			)
				throw error;
			// At 1 sat/vB the fee of a split of one coin is its size.
			const one = this.buildSplit(source, address, amount, 1, 1);
			const rate = Math.min(
				wanted,
				Math.max(least, one ? Math.floor(Number(cap) / one.fee) : least)
			);
			return {
				...this.fitSplit(source, address, amount, most, rate, cap),
				rate
			};
		}
	}
	/**
	 * Settle every split replacement the journal records. One whose answer
	 * never came went out when the wallet lists a coin of it, or when the
	 * wallet lists no fee coin of the split and the server knows the
	 * replacement. It did not when the wallet lists a confirmed output of
	 * the split or of a split it replaced. While the wallet lists every fee
	 * coin of the split, unconfirmed, it is sent again when `resend` is set,
	 * and dropped when refused, or when the wallet lists only some of them: a
	 * spend took one, which the replacement would throw out. Not sent again,
	 * it went out when the server knows it, the wallet's listing lagging.
	 */
	private async settleReplacements(resend: boolean): Promise<void> {
		let resent = false;
		for (const row of [...(this.journal.unconfirmed ?? [])]) {
			const replacement = row.replacement;
			if (!replacement) continue;
			const txid = this.txidOf(row)!,
				listed = this.wallet.listUtxos!();
			// A replacement belongs to the split it was recorded for, the last
			// of the splits it replaced. One that the row of another split
			// carries was copied there by a release that does not know the
			// record, when it replaced the split itself: it does not replace
			// the split that stands, and it is not sent again.
			const own =
				replacement.prior?.[replacement.prior.length - 1]?.txid === txid;
			let out: boolean | undefined;
			if (listed.some((c) => c.tx_hash.toLowerCase() === replacement.txid))
				out = true;
			// A block took the split, or a split it replaced: the replacement
			// spends the same source, so it is not out.
			else if (
				[txid, ...(row.prior ?? []).map((old) => old.txid)].some((id) =>
					listed.some((c) => c.tx_hash.toLowerCase() === id && c.height > 0)
				)
			)
				out = false;
			else if (
				resend &&
				listed.some(
					(c) => c.tx_hash.toLowerCase() === txid && c.tx_pos < row.count
				)
			) {
				out =
					own &&
					this.replaceable(txid) &&
					!(
						await this.bounded('a broadcast', () =>
							this.wallet.electrum.broadcastTransaction({
								rawTx: replacement.signed!
							})
						)
					).isErr();
				resent ||= out;
			} else {
				// Not sent again, or the wallet lists no fee coin of the split:
				// whether it went out is the server's to say, for the wallet's
				// listing may lag behind it.
				out = await this.known(replacement.txid!);
			}
			// The server cannot say, as one without a txindex answers of every
			// transaction not in its mempool: the record stays, with its split,
			// and the selection goes on.
			if (out === undefined) continue;
			this.settleReplacement(txid, out);
		}
		// The wallet lists the coins of a replacement it took only once it is
		// refreshed; until then they are not frozen, and a send of the wallet
		// that refreshes on its own could take one.
		if (resent) await this.refresh();
		// A charge whose split's row a release that does not know charges
		// dropped. The replacement went out when the wallet lists a confirmed
		// output of it, and did not when it lists a confirmed output of the
		// split it replaces, or the server does not know it. Until one of
		// those it stays charged.
		const carried = new Set(
			(this.journal.unconfirmed ?? []).flatMap((row) =>
				row.replacement?.txid ? [row.replacement.txid] : []
			)
		);
		const loose = (this.journal.charges ?? []).filter(
			(charge) => !carried.has(charge.txid)
		);
		if (!loose.length) return;
		const listed = this.wallet.listUtxos!();
		const confirmedIn = (txid: string): boolean =>
			listed.some((c) => c.tx_hash.toLowerCase() === txid && c.height > 0);
		const settled = new Map<string, boolean>();
		for (const charge of loose) {
			if (confirmedIn(charge.txid)) settled.set(charge.txid, true);
			else if (
				confirmedIn(charge.split) ||
				(await this.known(charge.txid)) === false
			)
				settled.set(charge.txid, false);
		}
		if (!settled.size) return;
		const next = copy(this.journal);
		for (const charge of loose)
			if (settled.get(charge.txid))
				next.spent = (
					BigInt(next.spent ?? '0') + BigInt(charge.over)
				).toString();
		const rest = (next.charges ?? []).filter(
			(charge) => !settled.has(charge.txid)
		);
		if (rest.length) next.charges = rest;
		else delete next.charges;
		this.save(next);
	}
	/**
	 * Forget the unconfirmed splits that need no replacement any more: one
	 * the wallet lists a confirmed output of, one whose fee coins the wallet
	 * listed and lists no longer, and one the wallet has yet to list that
	 * its server does not know. When a block
	 * took a split that was replaced, in place of its replacement, the coins
	 * are the same outputs of that split and are held under its id again.
	 */
	private async settleUnconfirmed(): Promise<void> {
		await this.settleReplacements(true);
		const rows = this.journal.unconfirmed ?? [];
		if (!rows.length) return;
		const live = this.wallet.listUtxos!();
		const keep: Preparation[] = [];
		let marked = false;
		const back: Array<{
			from: string;
			to: { txid: string; signed: string; fee: string };
			fee: string;
		}> = [];
		for (const row of rows) {
			// A split whose replacement the server could not say of stays as it
			// is until that replacement is settled.
			if (row.replacement) {
				keep.push(row);
				continue;
			}
			const txid = this.txidOf(row)!;
			const of = (id: string): ISpliceUtxo[] =>
				live.filter((c) => c.tx_hash.toLowerCase() === id);
			const won = (row.prior ?? []).find((old) =>
				of(old.txid).some((c) => c.height > 0)
			);
			if (won) {
				back.push({ from: txid, to: won, fee: row.fee });
				continue;
			}
			const outputs = of(txid);
			if (outputs.some((c) => c.height > 0)) continue;
			const fees = outputs.some((c) => c.tx_pos < row.count);
			if (row.listed) {
				// Listed before and not now: spent, or out of the mempool.
				if (fees) keep.push(row);
				continue;
			}
			if (fees) {
				keep.push({ ...row, listed: true });
				marked = true;
				continue;
			}
			if ((await this.known(txid)) === false) continue;
			keep.push(row);
		}
		if (keep.length === rows.length && !marked) return;
		const next = copy(this.journal);
		for (const { from, to, fee } of back) {
			this.move(next, from, to, false);
			// Charged what the split a block took paid, not its replacement.
			next.spent = (
				BigInt(next.spent ?? '0') -
				(BigInt(fee) - BigInt(to.fee))
			).toString();
		}
		if (keep.length) next.unconfirmed = keep;
		else delete next.unconfirmed;
		this.save(next);
	}
	/**
	 * Whether the unconfirmed split `txid` can be replaced by one that pays
	 * more: the pool follows it, the wallet lists every fee coin of it, none
	 * confirmed, and lists its change, when it has one, unfrozen. With a fee
	 * coin spent, the spend that took it would be thrown out with it; with
	 * the change spent or pledged, a payment, funding or splice of the
	 * wallet would be.
	 */
	private replaceable(txid: string): boolean {
		const entry = (this.journal.unconfirmed ?? []).find(
			(row) => this.txidOf(row) === txid
		);
		if (!entry) return false;
		const listed = this.wallet.listUtxos!().filter(
			(c) => c.tx_hash.toLowerCase() === txid
		);
		const outputs = listed.filter((c) => c.tx_pos < entry.count);
		if (outputs.length !== entry.count || outputs.some((c) => c.height > 0))
			return false;
		const change = entry.signed
			? bitcoin.Transaction.fromHex(entry.signed).outs.length > entry.count
			: true;
		return (
			!change ||
			listed.some(
				(c) =>
					c.tx_pos === entry.count &&
					!this.wallet.isUtxoFrozen!(c.tx_hash, c.tx_pos)
			)
		);
	}
	/**
	 * Whether a selection that asks `rate` and wants confirmed coins may wait
	 * for the unconfirmed split `txid`: the split pays that rate, or can be
	 * replaced by one that does within the cap of a split. Where that cap
	 * holds every split below the rate, the most a split of the pool's own
	 * could pay stands for the rate: a split of one fee coin is the smallest
	 * and pays the most, so a split of more coins that the cap holds lower is
	 * passed by one of fewer coins and is not waited on.
	 */
	private awaitable(txid: string, rate: number): boolean {
		const entry = (this.journal.unconfirmed ?? []).find(
			(row) => this.txidOf(row) === txid
		);
		if (entry === undefined) return false;
		const cap = Number(this.policy.maxPreparationFeeSatoshis);
		// The highest rate a split of `count` such fee coins pays within it.
		const reach = (count: number): number => {
			const size = this.buildSplit(
				entry.source,
				entry.address,
				entry.amount,
				count,
				1
			);
			return size ? Math.floor(cap / size.fee) : 0;
		};
		const goal = Math.min(
			rate,
			Math.max(reach(1), this.policy.preparationFeeRatePerVbyte ?? 1)
		);
		return (
			(entry.rate ?? 1) >= goal ||
			(this.replaceable(txid) && reach(entry.count) >= goal)
		);
	}
	/**
	 * Whether a raise asked at `rate` lets go of the action's `coin`: its
	 * split has not confirmed, cannot be replaced by one that pays that rate,
	 * and pays less. The pool follows its own unconfirmed splits. One a
	 * reorganisation put back in the mempool after the pool let it go is
	 * known by the wallet's listing of its outputs, and what it pays is read
	 * from its transaction and that of its source; when that cannot be read,
	 * the coin is let go of.
	 */
	private async stuck(
		coin: Coin,
		rate: number,
		live: ISpliceUtxo[]
	): Promise<boolean> {
		const txid = coin.utxo.tx_hash.toLowerCase();
		if (
			(this.journal.unconfirmed ?? []).some((row) => this.txidOf(row) === txid)
		)
			return !this.awaitable(txid, rate);
		const outputs = live.filter((c) => c.tx_hash.toLowerCase() === txid);
		if (!outputs.length || outputs.some((c) => c.height > 0)) return false;
		try {
			const split = bitcoin.Transaction.fromHex(coin.previous);
			let fee = 0n;
			for (const input of split.ins) {
				const source = bitcoin.Transaction.fromHex(
					await this.previous(Buffer.from(input.hash).reverse().toString('hex'))
				);
				fee += BigInt(source.outs[input.index].value);
			}
			for (const output of split.outs) fee -= BigInt(output.value);
			return fee < BigInt(Math.ceil(split.virtualSize() * rate));
		} catch (error) {
			if (timedOut(error)) throw error;
			return true;
		}
	}
	/**
	 * Replace a split that has not confirmed by one that pays more, when one
	 * is due: in the next block when the spend that waits is asked at a
	 * higher rate than the split pays, and otherwise as many blocks after it
	 * went out as FIXED_OUTPUT_FEE_TIMING says (fewer when the deadline of
	 * the spend is near), never twice in a block. Only a
	 * split all of whose fee coins the wallet still lists is replaced: with
	 * one spent, the spend that took it would be thrown out with it. Answers
	 * the id of the split that now stands.
	 */
	private async raiseIfDue(
		txid: string,
		wanted: number,
		opts: IFeeBumpSelectionOpts
	): Promise<string> {
		const height = opts.blockHeight;
		const entry = (this.journal.unconfirmed ?? []).find(
			(row) => this.txidOf(row) === txid.toLowerCase()
		);
		if (height === undefined || !entry) return txid;
		if (entry.at === undefined) {
			// Recorded without a height: the count of blocks begins now.
			const next = copy(this.journal);
			next.unconfirmed!.find((row) => this.txidOf(row) === txid)!.at = height;
			this.save(next);
			return txid;
		}
		if (!this.due(entry, wanted, opts) || !this.replaceable(txid)) return txid;
		const replaced = await this.raiseSplit(entry, wanted, height);
		if (!replaced) return txid;
		await this.refresh();
		await this.freezeCoins();
		return replaced;
	}
	/**
	 * Whether the replacement of the unconfirmed split `entry` is due for a
	 * spend asked at `wanted`: in the next block when the spend is asked at a
	 * higher rate than the split pays, and otherwise as many blocks after it
	 * went out as FIXED_OUTPUT_FEE_TIMING says (fewer when the deadline of
	 * the spend is near), never twice in a block.
	 */
	private due(
		entry: Preparation,
		wanted: number,
		opts: IFeeBumpSelectionOpts
	): boolean {
		const height = opts.blockHeight;
		if (height === undefined || entry.at === undefined) return false;
		const near =
			opts.deadlineHeight !== undefined &&
			opts.deadlineHeight - height <=
				FIXED_OUTPUT_FEE_TIMING.nearDeadlineBlocks;
		return (
			height > entry.at &&
			(wanted > (entry.rate ?? 1) ||
				height - entry.at >=
					(near
						? FIXED_OUTPUT_FEE_TIMING.splitRaiseBlocksNearDeadline
						: FIXED_OUTPUT_FEE_TIMING.splitRaiseBlocks))
		);
	}
	/**
	 * The replacement of the unconfirmed split `entry` for a spend asked at
	 * `wanted`, unsigned: the same source and fee coins, at the rate asked or
	 * the least a replacement must add, whichever is more, or at the highest
	 * rate the cap of a split pays for when that is less. Undefined when no
	 * replacement within that cap pays enough more to replace the split.
	 */
	private raisePlan(
		entry: Preparation,
		wanted: number
	): { unsigned: string; fee: number; rate: number } | undefined {
		const cap = this.policy.maxPreparationFeeSatoshis,
			was = entry.rate ?? 1;
		const at = (rate: number): { unsigned: string; fee: number } | undefined =>
			this.buildSplit(
				entry.source,
				entry.address,
				entry.amount,
				entry.count,
				rate
			);
		let rate = Math.max(
			wanted,
			was + 1,
			Math.ceil((was * SPLIT_RAISE_NUMERATOR) / SPLIT_RAISE_DENOMINATOR)
		);
		let built = at(rate);
		if (built && BigInt(built.fee) > cap) {
			// The highest rate the cap of a split still pays for.
			const size = at(1);
			rate = size ? Math.floor(Number(cap) / size.fee) : 0;
			built = rate > was ? at(rate) : undefined;
		}
		if (!built || BigInt(built.fee) > cap) return undefined;
		if (
			BigInt(built.fee) <
			BigInt(entry.fee) + BigInt(Math.ceil(built.fee / rate))
		)
			return undefined;
		return { ...built, rate };
	}
	/**
	 * Build, sign and send the replacement of an unconfirmed split: the same
	 * source, the same fee coins at the same positions, and a fee that the
	 * rules of replacement take (more in all than the split it replaces by
	 * at least 1 sat/vB of its own size, and a higher rate), within the cap
	 * of a split and the lifetime budget. Once the network took it, every
	 * coin of the old split the pool or an action holds becomes the coin at
	 * the same position of the new one. Answers the new id, or undefined
	 * with nothing changed.
	 */
	private async raiseSplit(
		entry: Preparation,
		wanted: number,
		height: number
	): Promise<string | undefined> {
		const cap = this.policy.maxPreparationFeeSatoshis;
		const before = {
			fee: BigInt(entry.fee),
			txid: this.txidOf(entry)!
		};
		const built = this.raisePlan(entry, wanted);
		if (!built) return undefined;
		const { rate } = built,
			fee = BigInt(built.fee);
		try {
			this.assertRoom(fee - before.fee);
		} catch (error) {
			if (error instanceof FixedOutputFeeError) return undefined;
			throw error;
		}
		const candidate: Preparation = {
			...copy(entry),
			state: 'unsigned',
			fee: String(built.fee),
			cap: cap.toString(),
			rate,
			unsigned: built.unsigned
		};
		delete candidate.signed;
		delete candidate.txid;
		delete candidate.listed;
		delete candidate.replacement;
		this.validateUnsigned(candidate);
		const result = this.wallet.signPsbtWithOurKey!(built.unsigned);
		if (result.isErr()) return undefined;
		const imported = this.wallet.importSignedPsbt!(
			(result as { isErr(): boolean; isOk(): boolean; value: string }).value,
			built.unsigned
		);
		if (imported.isErr()) return undefined;
		const signed = (
			imported as {
				isErr(): boolean;
				isOk(): boolean;
				value: { txHex: string };
			}
		).value.txHex;
		this.validateSigned(candidate, signed);
		const txid = bitcoin.Transaction.fromHex(signed).getId();
		// Recorded before it is sent, as the first form of a split is: a
		// wallet that answers past the bound, or a stop, leaves it in the
		// journal for the next selection to settle. The split was charged its
		// fee when it was closed: the replacement is charged what it pays over
		// that, in the journal's charges, until it is settled.
		const next = copy(this.journal);
		next.unconfirmed = next.unconfirmed!.map((row) =>
			this.txidOf(row) === before.txid
				? {
						...row,
						replacement: {
							...candidate,
							state: 'published' as const,
							signed,
							txid,
							at: height,
							raises: (entry.raises ?? 0) + 1,
							prior: [
								...(entry.prior ?? []),
								{ txid: before.txid, signed: entry.signed!, fee: entry.fee }
							]
						}
				  }
				: row
		);
		next.charges = [
			...(next.charges ?? []).filter((charge) => charge.txid !== txid),
			{ txid, split: before.txid, over: (fee - before.fee).toString() }
		];
		this.save(next);
		const sent = await this.bounded('a broadcast', () =>
			this.wallet.electrum.broadcastTransaction({ rawTx: signed })
		);
		this.settleReplacement(before.txid, !sent.isErr());
		return sent.isErr() ? undefined : txid;
	}
	/**
	 * The replacement recorded for the unconfirmed split `txid` went out, or
	 * did not. Once out, the coins of the split are its coins at the same
	 * positions, it stands in the split's place, and what it paid is spent;
	 * otherwise it is dropped, and the charge its record carried with it.
	 */
	private settleReplacement(txid: string, out: boolean): void {
		const next = copy(this.journal),
			row = next.unconfirmed?.find((r) => this.txidOf(r) === txid),
			replacement = row?.replacement;
		if (!row || !replacement) return;
		const charges = (next.charges ?? []).filter(
			(charge) => charge.txid !== replacement.txid
		);
		if (charges.length) next.charges = charges;
		else delete next.charges;
		const recorded = replacement.prior?.[replacement.prior.length - 1];
		if (out) {
			// It stands in the place of this split, which it replaced with
			// every split this one replaced.
			const stands: Preparation =
				recorded?.txid === txid
					? replacement
					: {
							...replacement,
							prior: [
								...(row.prior ?? []),
								{ txid, signed: row.signed!, fee: row.fee }
							]
					  };
			delete stands.replacement;
			this.move(
				next,
				txid,
				{ txid: replacement.txid!, signed: replacement.signed! },
				true
			);
			next.unconfirmed = next.unconfirmed!.map((r) => (r === row ? stands : r));
			// What was spent holds the fee of this split. The replacement paid
			// its own in its place: the charge its record carried, and what this
			// split paid over the split that record was made for, when another
			// release replaced it, are both in that.
			next.spent = (
				BigInt(next.spent ?? '0') +
				BigInt(replacement.fee) -
				BigInt(row.fee)
			).toString();
		} else delete row.replacement;
		this.save(next);
	}
	/**
	 * A signed split the network refused, that the wallet's server never
	 * took, is built again from the same source at the rate the policy gives
	 * now, within the policy's cap.
	 */
	private rebuild(row: Preparation): Preparation {
		const rate = this.policy.preparationFeeRatePerVbyte ?? 1,
			cap = this.policy.maxPreparationFeeSatoshis;
		const plan = this.fitSplit(
			row.source,
			row.address,
			row.amount,
			row.count,
			rate,
			cap
		);
		const more = BigInt(plan.fee) - BigInt(row.fee);
		if (more > 0n) this.assertRoom(more);
		const rebuilt: Preparation = {
			id: row.id,
			state: 'unsigned',
			source: row.source,
			address: row.address,
			amount: row.amount,
			count: plan.count,
			fee: String(plan.fee),
			cap: cap.toString(),
			rate,
			unsigned: plan.unsigned
		};
		this.validateUnsigned(rebuilt);
		const next = copy(this.journal);
		next.preparations = next.preparations.map((p) =>
			p.id === row.id ? rebuilt : p
		);
		this.save(next);
		this.unsavedSigned.delete(row.id);
		return rebuilt;
	}
	/** Take one split as far as the wire. Throws what stops it; the row stays. */
	private async resume(row: Preparation): Promise<void> {
		if (row.state === 'building') {
			// Recorded before it was computed, by an older journal. It has no
			// signing intent, so nothing can have followed it.
			await this.abandon(row);
			return;
		}
		if (row.state === 'unsigned') {
			const current = this.wallet.listUtxos!().find(
				(u) => key(u) === key(row.source.utxo)
			);
			let whole =
				current !== undefined &&
				current.value === row.source.utxo.value &&
				current.path === row.source.utxo.path &&
				current.publicKey === row.source.utxo.publicKey;
			if (whole)
				try {
					this.validateUnsigned(row);
				} catch {
					whole = false;
				}
			if (!whole) {
				// Its source is no longer unspent and owned, or the split no
				// longer passes its own checks. It was never signed for the
				// wire, so it is dropped and its source released.
				await this.abandon(row);
				return;
			}
			if (current!.height <= 0)
				throw new FixedOutputFeePreparationPendingError(current!.tx_hash);
			await this.freeze(
				row.source.utxo.tx_hash,
				row.source.utxo.tx_pos,
				this.prefix + ':source:' + row.id
			);
			let signed = this.unsavedSigned.get(row.id);
			if (!signed) {
				const result = this.wallet.signPsbtWithOurKey!(row.unsigned!);
				if (result.isErr())
					throw new FixedOutputFeeError(
						'FEE_PREPARATION_SIGNING_FAILED',
						'operator',
						'Fixed-output split signing failed'
					);
				const imported = this.wallet.importSignedPsbt!(
					(result as { isErr(): boolean; isOk(): boolean; value: string })
						.value,
					row.unsigned!
				);
				if (imported.isErr())
					throw new FixedOutputFeeError(
						'FEE_PREPARATION_SIGNING_FAILED',
						'operator',
						'Fixed-output split signature validation failed'
					);
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
			this.updatePreparation(row.id, {
				state: 'signed',
				signed,
				txid: bitcoin.Transaction.fromHex(signed).getId()
			});
			this.unsavedSigned.delete(row.id);
			row = this.journal.preparations.find((p) => p.id === row.id)!;
		}
		this.validateSigned(row, row.signed!);
		const sourceLive = this.wallet.listUtxos!().some(
			(c) => key(c) === key(row.source.utxo)
		);
		// With the source gone the split is on the wire, or its source went
		// elsewhere: the look after the next refresh tells which.
		if (!sourceLive) return;
		if (row.observed) this.updatePreparation(row.id, { observed: false });
		const result = await this.bounded('a broadcast', () =>
			this.wallet.electrum.broadcastTransaction({ rawTx: row.signed! })
		);
		if (result.isErr()) {
			if (
				row.state === 'signed' &&
				(this.policy.preparationFeeRatePerVbyte ?? 1) > (row.rate ?? 1)
			)
				return this.resume(this.rebuild(row));
			throw new FixedOutputFeeError(
				'FEE_PREPARATION_NOT_PUBLISHED',
				'wait',
				'Fixed-output split publication failed; exact candidate retained'
			);
		}
		if (row.state !== 'published')
			this.updatePreparation(row.id, { state: 'published' });
	}
	/**
	 * After a refresh: what became of a split that has a signature. Its fee
	 * coins the wallet lists are taken into the pool and the split is closed.
	 * One whose source is gone and whose coins are not listed is closed too,
	 * at the second look when the wallet knows its transaction (the coins
	 * were spent), and at once when it does not (the source went elsewhere).
	 */
	private async observe(row: Preparation): Promise<void> {
		if (row.state !== 'signed' && row.state !== 'published') return;
		const live = this.wallet.listUtxos!();
		if (live.some((c) => key(c) === key(row.source.utxo))) return;
		const txid = this.txidOf(row)!;
		const outputs = live.filter(
			(c) =>
				c.tx_hash.toLowerCase() === txid &&
				c.tx_pos < row.count &&
				c.value === row.amount &&
				c.address === row.address
		);
		if (!outputs.length && !row.observed) {
			const known = await this.known(txid);
			if (known === undefined) return;
			if (known) {
				this.updatePreparation(row.id, { state: 'published', observed: true });
				return;
			}
		}
		this.close(row, outputs);
	}
	/** Every split, each on its own: one that cannot go on stops no other. */
	private async each(
		step: (row: Preparation) => Promise<void>,
		failures: Map<string, Error>
	): Promise<void> {
		for (const row of this.journal.preparations.map((p) => copy(p))) {
			if (failures.has(row.id)) continue;
			try {
				await step(row);
			} catch (error) {
				// A wallet that does not answer ends the whole selection.
				if (timedOut(error)) throw error;
				failures.set(row.id, error as Error);
			}
		}
	}

	async select(
		targetFeeSats: bigint,
		feeratePerKw: number,
		opts: IFeeBumpSelectionOpts
	): Promise<Selection> {
		try {
			return await this.locked(async () => {
				// Near its deadline a claim passes over a coin of a split that
				// cannot pay its rate for a split of the pool's own. When that
				// split cannot be had, a wallet that does not answer in time
				// included, the selection is made again without passing over: a
				// spend that waits on a slow parent can still confirm, and one
				// with no fee input cannot go out at all.
				const prefer = { over: false };
				try {
					return await this.selectLocked(
						targetFeeSats,
						feeratePerKw,
						opts,
						undefined,
						prefer
					);
				} catch (error) {
					if (!prefer.over) throw error;
					return this.selectLocked(targetFeeSats, feeratePerKw, opts);
				}
			});
		} catch (error) {
			if (error instanceof FixedOutputFeeError)
				this.lastRefusal = {
					code: error.code,
					// Waiting is no remedy once it cannot make the deadline.
					remedy:
						error.remedy === 'wait' &&
						opts.blockHeight !== undefined &&
						opts.deadlineHeight !== undefined &&
						!fixedOutputFeeWaitMakesDeadline(
							opts.blockHeight,
							opts.deadlineHeight
						)
							? 'none'
							: error.remedy,
					at: Date.now(),
					...(opts.deadlineHeight !== undefined
						? { deadlineHeight: opts.deadlineHeight }
						: {})
				};
			throw error;
		}
	}
	/** An unfrozen P2WPKH coin of the wallet that the pool does not hold. */
	private ordinary(coin: ISpliceUtxo, reserved: Set<string>): boolean {
		if (
			reserved.has(key(coin)) ||
			this.wallet.isUtxoFrozen!(coin.tx_hash, coin.tx_pos)
		)
			return false;
		try {
			return bitcoin.address.toOutputScript(coin.address, this.network).equals(
				bitcoin.payments.p2wpkh({
					pubkey: Buffer.from(coin.publicKey, 'hex')
				}).output!
			);
		} catch {
			return false;
		}
	}
	/**
	 * What the pool holds and can do, from the stored journal and the
	 * wallet's listing as they are: nothing is refreshed, written or frozen.
	 * `forFeeSatoshis` is the fee coin a split is measured for, the policy's
	 * maxFeeSatoshis when left out.
	 */
	status(forFeeSatoshis?: bigint): IFixedOutputFeePoolState {
		const fee = forFeeSatoshis ?? this.policy.maxFeeSatoshis;
		if (!positive(fee)) throw new Error('Invalid fixed-output fee amount');
		const { journal, reserved } = this.latest();
		const live = this.wallet.listUtxos!();
		const listed = new Map(live.map((coin) => [key(coin), coin]));
		const feeCoins = { ready: 0, readySatoshis: 0n, unconfirmed: 0 };
		for (const coin of journal.coins ?? []) {
			const current = listed.get(key(coin.utxo));
			if (!current) continue;
			if (current.height > 0) {
				feeCoins.ready++;
				feeCoins.readySatoshis += BigInt(current.value);
			} else feeCoins.unconfirmed++;
		}
		const needed =
			(fee > BigInt(DUST) ? fee : BigInt(DUST)) +
			this.policy.maxPreparationFeeSatoshis;
		const largest = live
			.filter((coin) => coin.height > 0 && this.ordinary(coin, reserved))
			.reduce(
				(most, coin) => (BigInt(coin.value) > most ? BigInt(coin.value) : most),
				0n
			);
		const usage = this.usage(journal);
		const reason =
			usage.reserved + usage.spent + this.policy.maxPreparationFeeSatoshis >
			this.policy.maxTotalFeeSatoshis
				? ('FEE_BUDGET_EXHAUSTED' as const)
				: largest < needed
				? ('FEE_FUNDS_UNAVAILABLE' as const)
				: undefined;
		return {
			available: true,
			budget: this.budgetOf(journal),
			feeCoins,
			actions: Object.values(journal.actions)
				.filter((action) => !action.retired)
				.map((action) => ({
					...(action.feeActionId !== undefined
						? { feeActionId: action.feeActionId }
						: {}),
					capSatoshis: BigInt(action.cap),
					inputs: action.inputs.length,
					heldSatoshis: action.inputs.reduce(
						(sum, coin) => sum + BigInt(coin.utxo.value),
						0n
					)
				})),
			splits: journal.preparations.flatMap((row) => {
				if (row.state === 'building') return [];
				const transactionId = this.txidOf(row);
				return [
					{
						state: row.state,
						...(transactionId !== undefined ? { transactionId } : {}),
						feeSatoshis: BigInt(row.fee),
						feeCoins: row.count,
						feeCoinSatoshis: BigInt(row.amount)
					}
				];
			}),
			preparation: {
				possible: reason === undefined,
				forFeeSatoshis: fee,
				neededSatoshis: needed,
				largestConfirmedSatoshis: largest,
				...(reason !== undefined ? { reason } : {})
			},
			...(this.lastRefusal ? { lastRefusal: { ...this.lastRefusal } } : {})
		};
	}
	private async selectLocked(
		targetFeeSats: bigint,
		feeratePerKw: number,
		opts: IFeeBumpSelectionOpts,
		// The split this same request just sent, on its second pass.
		sent?: string,
		// Given when a split of the pool's own may be preferred to a coin of a
		// split that cannot pay the rate; `over` is set when it was.
		prefer?: { over: boolean }
	): Promise<Selection> {
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
		if (
			opts.replacedTxid !== undefined &&
			!/^[a-f0-9]{64}$/i.test(opts.replacedTxid)
		)
			throw new Error('Invalid replaced fee transaction');
		this.reload();
		await this.completeRetirements();
		if (this.isRetired(id))
			throw new FixedOutputFeeError(
				'FEE_ACTION_RETIRED',
				'none',
				'Fixed-output fee action is retired'
			);
		await this.releaseOrphans();
		const failures = new Map<string, Error>();
		await this.refresh();
		await this.each((row) => this.resume(row), failures);
		await this.refresh();
		await this.each((row) => this.observe(row), failures);
		const derived = copy(this.journal);
		if (this.recordMoves(derived)) this.save(derived);
		await this.settleUnconfirmed();
		if (!Object.prototype.hasOwnProperty.call(this.journal.actions, id)) {
			// A new action: the only place the policy's budget and its
			// per-transaction cap are applied. It is measured once the splits
			// are settled, so that a split replacement that was recorded and
			// refused is no longer charged.
			this.assertRoom(requestedCap);
			const next = copy(this.journal);
			next.actions[id] = {
				cap: requestedCap.toString(),
				feeActionId: actionId,
				inputs: []
			};
			this.save(next);
		}
		const splitAt = this.splitRate(feeratePerKw);
		// The coins of a split that replaced another are on their way until
		// the wallet has listed them.
		const onTheWay = (): Set<string> =>
			new Set(
				(this.journal.unconfirmed ?? [])
					.filter((row) => !row.listed)
					.map((row) => this.txidOf(row)!)
			);
		const live = this.wallet.listUtxos!();
		const listed = new Map(live.map((coin) => [key(coin), coin]));
		const stays = (coin: Coin): boolean =>
			listed.has(key(coin.utxo)) ||
			onTheWay().has(coin.utxo.tx_hash.toLowerCase());
		// A free fee coin the wallet no longer lists was spent, or its split
		// left the chain: it is no longer the pool's.
		if ((this.journal.coins ?? []).some((c) => !stays(c))) {
			const next = copy(this.journal);
			next.coins = next.coins!.filter((c) => stays(c));
			this.save(next);
		}
		await this.freezeCoins();
		const excluded = new Set(
			(opts.excludeTxids ?? []).map((s) => s.toLowerCase())
		);
		const action = this.journal.actions[id];
		// The cap the action was recorded with, or the caller's own when that
		// is stricter. A policy lowered since does not reach a recorded action.
		const cap =
			opts.maxFeeSatoshis !== undefined &&
			opts.maxFeeSatoshis < BigInt(action.cap)
				? opts.maxFeeSatoshis
				: BigInt(action.cap);
		// A spend made before a coin of the action moved names the coin where
		// it was. It is served with the coin where it is now, so that its next
		// form spends a coin that exists: the action keeps its place in a
		// split that follows the rate, and a raise is never refused for it.
		const replacementKeys = new Set(
			(opts.replacementInputs ?? []).map((i) =>
				this.locate(action, `${i.txid.toLowerCase()}:${i.vout}`)
			)
		);
		// A request that names the transaction it replaces takes confirmed
		// coins only, whether or not it names that transaction's fee coins (the
		// node's second request after a raise refused for good names none): a
		// replacement may spend an unconfirmed coin only when a transaction it
		// replaces spent it (BIP 125 rule 2).
		const confirmed =
			opts.confirmedOnly === true ||
			replacementKeys.size > 0 ||
			opts.replacedTxid !== undefined;
		// The transaction a caller replaces holds its fee inputs only while
		// the wallet's server knows it. One that was refused, or was never
		// sent, spends nothing: an input of it that the wallet no longer
		// lists went elsewhere.
		const replacedUnknown =
			opts.replacedTxid !== undefined &&
			replacementKeys.size > 0 &&
			(await this.known(opts.replacedTxid.toLowerCase())) === false;
		const kept: Coin[] = [],
			gone = [...(action.gone ?? [])];
		for (const coin of action.inputs) {
			this.checkCoin(coin);
			const txid = coin.utxo.tx_hash.toLowerCase();
			if (excluded.has(txid))
				throw new FixedOutputFeeError(
					'FEE_INPUT_UNAVAILABLE',
					'none',
					'Reserved fixed-output fee input is unavailable'
				);
			if (replacementKeys.size > 0 && (await this.stuck(coin, splitAt, live))) {
				// A raise lets go of a coin of a split that has not confirmed,
				// cannot be replaced, and pays less than the rate asked: a spend
				// that kept it would wait on that split. That holds as well for
				// a split a reorganisation put back in the mempool after the
				// pool let it go, which the pool no longer follows. The raise still
				// replaces the spend through the output both spend, and is
				// funded from confirmed coins. The spend it replaces may still
				// be the one a block takes, so the coin is counted as gone.
				gone.push({ outpoint: key(coin.utxo), value: coin.utxo.value });
			} else if (
				stays(coin) ||
				(replacementKeys.has(key(coin.utxo)) && !replacedUnknown)
			)
				kept.push(coin);
			// A reserved coin the wallet no longer lists is gone, unless it
			// is an input of a transaction the caller replaces that the
			// wallet's server knows: the action lets go of it and is funded
			// from another.
			else gone.push({ outpoint: key(coin.utxo), value: coin.utxo.value });
		}
		// A named coin the action no longer holds is served without: one it
		// let go of, in this selection or an earlier one whose answer the node
		// may not have taken up, is still spent by the transaction replaced,
		// and the raise replaces that transaction through the output both
		// spend; and a transaction the wallet's server does not know spends
		// nothing. Only a coin the action never held is refused.
		for (const wanted of replacementKeys)
			if (
				!kept.some((coin) => key(coin.utxo) === wanted) &&
				!gone.some((coin) => coin.outpoint === wanted) &&
				!replacedUnknown
			)
				throw new FixedOutputFeeError(
					'FEE_INPUT_UNAVAILABLE',
					'none',
					'Unreserved fixed-output replacement input'
				);
		const selected = [...kept];
		let sum = selected.reduce((total, c) => total + BigInt(c.utxo.value), 0n);
		// A raise of a transaction it names, that the wallet's server may
		// know, pays more than that transaction by the relay rate of 1 sat/vB
		// on its own size (BIP 125), or the network keeps the transaction it
		// replaces. That transaction burned whole the fee coins it names:
		// those the action keeps, and those it let go of.
		const values = new Map<string, bigint>([
			...gone.map((coin): [string, bigint] => [
				coin.outpoint,
				BigInt(coin.value)
			]),
			...action.inputs.map((coin): [string, bigint] => [
				key(coin.utxo),
				BigInt(coin.utxo.value)
			])
		]);
		// A request that names the transaction it replaces and none of its fee
		// coins, as the node's second request after a raise refused for good,
		// reads those coins from that transaction, when the wallet's server
		// has it. One the server does not know spends nothing, and there is
		// nothing to pay over. One it cannot give and may know, as a server
		// without a txindex answers of every spend not in its mempool, is
		// reckoned to have paid every coin the action holds or let go of: the
		// most a spend of the action's coins can have paid, so that a raise
		// never pays less than it, and never waits on the server. Coins that
		// spend never spent together may pass the action's cap: the raise is
		// then served with what fits within the cap (below).
		let paidKeys = replacementKeys,
			reckoned = false;
		if (!replacementKeys.size && opts.replacedTxid !== undefined) {
			const replaced = opts.replacedTxid.toLowerCase();
			let raw: string | undefined;
			try {
				raw = (
					await this.bounded('a transaction lookup', () =>
						this.host.previousTransactions([replaced])
					)
				).get(replaced);
			} catch (error) {
				if (timedOut(error)) throw error;
			}
			if (raw)
				paidKeys = new Set(
					bitcoin.Transaction.fromHex(raw).ins.map((input) =>
						this.locate(
							action,
							`${Buffer.from(input.hash).reverse().toString('hex')}:${
								input.index
							}`
						)
					)
				);
			else if ((await this.known(replaced)) !== false) {
				paidKeys = new Set(values.keys());
				reckoned = true;
			}
		}
		const replacedPaid =
			opts.replacedTxid === undefined || replacedUnknown
				? 0n
				: [...paidKeys].reduce(
						(total, outpoint) => total + (values.get(outpoint) ?? 0n),
						0n
				  );
		// The size of the spend on its own, from the fee it is asked to pay at
		// its rate. A rate in sat/kw is a rate in sat/vB rounded up (as
		// satPerVbyteToSatPerKw has it), so the size is reckoned at the least
		// rate that rounds to it: it may come out a little long, never short.
		const ownVbytes = Math.ceil(
			(Number(targetFeeSats) * 250) / Math.max(1, feeratePerKw - 1)
		);
		const target = (count: number): bigint => {
			const asked =
				targetFeeSats +
				spliceFeeSats(count * P2WPKH_INPUT_WEIGHT, feeratePerKw);
			if (replacedPaid === 0n) return asked;
			const relayed =
				replacedPaid +
				BigInt(ownVbytes + Math.ceil((count * P2WPKH_INPUT_WEIGHT) / 4));
			return relayed > asked ? relayed : asked;
		};
		const frozen = new Map(
			this.wallet.listFrozenUtxos!().map((coin) => [key(coin), coin.freezeTag])
		);
		// Only the pool's own fee coins: an ordinary coin is never burned
		// whole, it goes through a split that pays its change back.
		const free = (this.journal.coins ?? [])
			.map((coin) => ({ coin, current: listed.get(key(coin.utxo))! }))
			.filter(
				({ coin, current }) =>
					current !== undefined &&
					!excluded.has(coin.utxo.tx_hash.toLowerCase()) &&
					(!frozen.has(key(coin.utxo)) ||
						frozen.get(key(coin.utxo)) === this.coinTag)
			)
			.sort((a, b) => a.current.value - b.current.value);
		// An unconfirmed coin is taken only from the pool's own split, and
		// not at all when the caller wants confirmed inputs.
		const remaining = free.filter(
			({ current }) => !confirmed || current.height > 0
		);
		const worth = (coins: typeof remaining): bigint =>
			coins.reduce((total, { current }) => total + BigInt(current.value), 0n);
		// The coins of `coins` that cover the target: at each step the
		// smallest that covers it alone, or, while none does, the largest
		// that fits the cap.
		const cover = (coins: typeof remaining): typeof remaining => {
			const left = [...coins],
				taken: typeof remaining = [];
			const count = (): number => selected.length + taken.length;
			while (
				left.length &&
				(sum + worth(taken) < target(count()) || !count())
			) {
				const total = sum + worth(taken);
				const adequate = left.findIndex(
					({ current }) =>
						total + BigInt(current.value) >= target(count() + 1) &&
						total + BigInt(current.value) <= cap
				);
				const index =
					adequate >= 0
						? adequate
						: left
								.map((entry, position) => ({ entry, index: position }))
								.reverse()
								.find(({ entry }) => total + BigInt(entry.current.value) <= cap)
								?.index;
				if (index === undefined) break;
				taken.push(left.splice(index, 1)[0]);
			}
			return taken;
		};
		// What a coin of a split that has not confirmed costs beyond itself,
		// by split: nothing when the split pays the rate asked, and what its
		// replacement pays over it when one is due now and pays that rate.
		// Undefined when the split cannot pay that rate now: a spend that took
		// the coin would wait on it.
		const parents = new Map<string, bigint | undefined>();
		const extra = (txid: string): bigint | undefined => {
			if (!parents.has(txid)) {
				const entry = (this.journal.unconfirmed ?? []).find(
					(row) => this.txidOf(row) === txid
				);
				let cost: bigint | undefined;
				if (entry && (entry.rate ?? 1) >= splitAt) cost = 0n;
				else if (
					entry &&
					this.due(entry, splitAt, opts) &&
					this.replaceable(txid)
				) {
					const plan = this.raisePlan(entry, splitAt);
					if (plan && plan.rate >= splitAt)
						cost = BigInt(plan.fee) - BigInt(entry.fee);
				}
				parents.set(txid, cost);
			}
			return parents.get(txid);
		};
		const parentOf = ({
			current
		}: {
			current: ISpliceUtxo;
		}): string | undefined =>
			current.height > 0 ? undefined : current.tx_hash.toLowerCase();
		// Fee coins are burned whole, so what is taken is the fee, with what
		// the replacement of a split its coins set off pays.
		const costOf = (coins: typeof remaining): bigint => {
			let total = worth(coins);
			for (const txid of new Set(coins.map(parentOf)))
				if (txid !== undefined) total += extra(txid) ?? 0n;
			return total;
		};
		const enough = (coins: typeof remaining): boolean =>
			selected.length + coins.length > 0 &&
			sum + worth(coins) >= target(selected.length + coins.length);
		// The coin that covers the target alone for least, or the coins each
		// too small to cover it alone when together they cover it for less.
		const choose = (coins: typeof remaining): typeof remaining => {
			if (enough([])) return [];
			const fits = coins.filter(
				({ current }) =>
					sum + BigInt(current.value) >= target(selected.length + 1) &&
					sum + BigInt(current.value) <= cap
			);
			if (!fits.length) return cover(coins);
			const single = fits.reduce((best, coin) =>
				costOf([coin]) < costOf([best]) ? coin : best
			);
			const first = coins.indexOf(fits[0]);
			const smaller = first > 0 ? cover(coins.slice(0, first)) : [];
			return smaller.length > 0 &&
				enough(smaller) &&
				costOf(smaller) < costOf([single])
				? smaller
				: [single];
		};
		// What a split of the pool's own is made for when no free coin covers
		// the target, and the coins of the wallet it may be made from.
		const retained = kept.reduce(
			(total, c) => total + BigInt(c.utxo.value),
			0n
		);
		const needed = target(kept.length + 1) - retained;
		const amount = needed > BigInt(DUST) ? needed : BigInt(DUST);
		const ordinaryCoins = (): ISpliceUtxo[] => {
			const reserved = this.latest().reserved;
			return live.filter(
				(coin) =>
					!excluded.has(coin.tx_hash.toLowerCase()) &&
					this.ordinary(coin, reserved)
			);
		};
		const large = (coin: ISpliceUtxo): boolean =>
			BigInt(coin.value) >= amount + this.policy.maxPreparationFeeSatoshis;
		const sourceOf = (coins: ISpliceUtxo[]): ISpliceUtxo | undefined =>
			coins
				.filter((coin) => coin.height > 0 && large(coin))
				.sort((a, b) => b.value - a.value)[0];
		// A spend with a deadline that may take a coin of the pool's own split
		// before the split confirmed takes it at once (below).
		const atOnce = !confirmed && opts.deadlineHeight !== undefined;
		// Whether such a split can be made now and its coin taken at once:
		// nothing it would wait on first, room for it in the action's cap and
		// in the budget, and a confirmed coin of the wallet to make it from.
		const splitNow = (): boolean => {
			if (
				!prefer ||
				!atOnce ||
				sent !== undefined ||
				failures.size > 0 ||
				this.journal.preparations.some(
					(p) => p.state === 'signed' || p.state === 'published'
				) ||
				(this.journal.coins ?? []).some((c) => !listed.has(key(c.utxo))) ||
				retained + amount > cap
			)
				return false;
			try {
				this.assertRoom(this.policy.maxPreparationFeeSatoshis);
			} catch (error) {
				if (error instanceof FixedOutputFeeError) return false;
				throw error;
			}
			return sourceOf(ordinaryCoins()) !== undefined;
		};
		// A coin of a split the pool follows that pays less than a split of its
		// own could, and cannot be replaced by one that pays that. What a split
		// the pool no longer follows pays is not known without its source.
		const stuckSplit = (coin: (typeof remaining)[number]): boolean => {
			const txid = parentOf(coin);
			return (
				txid !== undefined &&
				(this.journal.unconfirmed ?? []).some(
					(row) => this.txidOf(row) === txid
				) &&
				!this.awaitable(txid, splitAt)
			);
		};
		// A coin of a split that cannot pay the rate now is taken only when
		// the other coins do not cover the target: a spend that took it would
		// wait on that split. For a spend that takes the coin of a split of
		// the pool's own at once, a coin of a split that cannot be brought to
		// pay what a split of the pool's own would is taken only after the
		// others, and never while such a split can be made now: that split
		// pays the rate asked, or the most the cap of a split allows, and the
		// two can confirm together.
		let chosen = choose(
			remaining.filter((coin) => {
				const txid = parentOf(coin);
				return txid === undefined || extra(txid) !== undefined;
			})
		);
		if (!enough(chosen) && atOnce)
			chosen = choose(remaining.filter((coin) => !stuckSplit(coin)));
		if (!enough(chosen)) {
			const all = choose(remaining);
			if (prefer && enough(all) && splitNow()) prefer.over = true;
			else chosen = all;
		}
		for (const { coin, current } of chosen) {
			const entry = { utxo: { ...current }, previous: coin.previous };
			this.checkCoin(entry);
			selected.push(entry);
			sum += BigInt(current.value);
		}
		// A pay-over reckoned for a spend the server could not give is served
		// with the coins taken when they fit the cap and pay the rate asked,
		// though they fall short of it.
		const fits =
			reckoned &&
			selected.length > 0 &&
			sum <= cap &&
			sum >=
				targetFeeSats +
					spliceFeeSats(selected.length * P2WPKH_INPUT_WEIGHT, feeratePerKw);
		if (!fits && (sum < target(selected.length) || !selected.length)) {
			if (retained + amount > cap)
				throw new FixedOutputFeeError(
					'FEE_ACTION_CAP_EXHAUSTED',
					'operator',
					'Fixed-output action fee cap exhausted'
				);
			// A split that stopped says why before another is begun.
			const failure = failures.values().next();
			if (!failure.done) throw failure.value;
			const unseen = this.journal.preparations.find(
				(p) => p.state === 'signed' || p.state === 'published'
			);
			if (unseen)
				throw new FixedOutputFeePreparationPendingError(this.txidOf(unseen)!);
			// It waits on a split that has not confirmed only while that split
			// pays the rate asked, or can be replaced by one that does: one
			// that is due is replaced now. A split a spend took a coin of
			// cannot be replaced, nor one a reorganisation put back after the
			// pool let it go. A claim that waited on it could pass its
			// deadline, so a split of its own is made instead.
			// It waits only when the coins it would have once those splits
			// confirm could cover it within its cap: the coins it keeps, and
			// every free coin, taken largest first.
			const later = free.filter(
				({ current }) =>
					current.height <= 0 &&
					this.awaitable(current.tx_hash.toLowerCase(), splitAt)
			);
			const couldCover = (coins: typeof free): boolean => {
				let total = retained,
					count = kept.length;
				for (const { current } of [...coins].sort(
					(a, b) => b.current.value - a.current.value
				)) {
					if (count > 0 && total >= target(count)) break;
					if (total + BigInt(current.value) > cap) continue;
					total += BigInt(current.value);
					count++;
				}
				return count > 0 && total >= target(count);
			};
			const awaited =
				confirmed && later.length && couldCover([...remaining, ...later])
					? later[0].current.tx_hash.toLowerCase()
					: undefined;
			if (awaited)
				throw new FixedOutputFeePreparationPendingError(
					await this.raiseIfDue(awaited, splitAt, opts)
				);
			// A coin of a split that was replaced, until the wallet lists it.
			const coming = (this.journal.coins ?? []).find(
				(c) => !listed.has(key(c.utxo))
			);
			if (coming)
				throw new FixedOutputFeePreparationPendingError(coming.utxo.tx_hash);
			if (sent) throw new FixedOutputFeePreparationPendingError(sent);
			const ordinary = ordinaryCoins();
			const source = sourceOf(ordinary);
			if (!source) {
				// The only fee coin may have just funded anchor CPFP. Its owned
				// change can prepare the HTLC fee after confirmation, so defer
				// only when that exact eligible source is authenticated.
				const waiting = ordinary.find(
					(coin) => coin.height <= 0 && large(coin)
				);
				if (waiting) {
					this.checkCoin({
						utxo: waiting,
						previous: await this.previous(waiting.tx_hash)
					});
					throw new FixedOutputFeePreparationPendingError(waiting.tx_hash);
				}
				throw new FixedOutputFeeError(
					'FEE_FUNDS_UNAVAILABLE',
					'operator',
					'No confirmed ordinary Bitcoin coin can prepare fixed-output fees'
				);
			}
			const coin: Coin = {
				utxo: { ...source },
				previous: await this.previous(source.tx_hash)
			};
			this.checkCoin(coin);
			const addressResult = await this.bounded('a change address request', () =>
				this.wallet.getChangeAddress!(EAddressType.p2wpkh)
			);
			if (addressResult.isErr())
				throw new FixedOutputFeeError(
					'FEE_WALLET_UNAVAILABLE',
					'wait',
					'Fixed-output fee address unavailable'
				);
			const address = (
				addressResult as {
					isErr(): boolean;
					isOk(): boolean;
					value: { address: string };
				}
			).value.address;
			this.owner(bitcoin.address.toOutputScript(address, this.network));
			// The split and its whole fee, before anything is recorded or
			// frozen: one that cannot fit its cap leaves nothing behind.
			// It pays the rate of the spend it is made for, never less than
			// the policy's own rate and never more than the cap of a split.
			const plan = this.planSplit(
				coin,
				address,
				Number(amount),
				Math.min(
					this.policy.feeCoinCount ?? 4,
					Number(
						(BigInt(source.value) - this.policy.maxPreparationFeeSatoshis) /
							amount
					)
				),
				splitAt
			);
			const rate = plan.rate;
			// A new split: its cap has room in the budget before it is recorded.
			this.assertRoom(this.policy.maxPreparationFeeSatoshis);
			const next = copy(this.journal),
				number = next.next ?? next.preparations.length,
				row: Preparation = {
					id: String(number),
					state: 'unsigned',
					source: coin,
					address,
					amount: Number(amount),
					count: plan.count,
					fee: String(plan.fee),
					cap: this.policy.maxPreparationFeeSatoshis.toString(),
					rate,
					...(opts.blockHeight !== undefined ? { at: opts.blockHeight } : {}),
					unsigned: plan.unsigned
				};
			this.validateUnsigned(row);
			next.preparations.push(row);
			next.next = number + 1;
			await this.freeze(
				source.tx_hash,
				source.tx_pos,
				this.prefix + ':source:' + row.id
			);
			this.save(next);
			await this.resume(row);
			await this.refresh();
			const made = this.txidOf(
				this.journal.preparations.find((p) => p.id === row.id)!
			)!;
			// A spend with a deadline that may take a coin of the pool's own
			// split before the split confirmed takes it at once, so that the
			// two can be in one block.
			if (!confirmed && !sent && opts.deadlineHeight !== undefined)
				return this.selectLocked(
					targetFeeSats,
					feeratePerKw,
					opts,
					made,
					prefer
				);
			throw new FixedOutputFeePreparationPendingError(made);
		}
		// A coin it takes or keeps of a split still unconfirmed has that split
		// pay the rate of its own spend first, when a replacement is due, so
		// that the two can confirm in one block. A coin it keeps counts as one
		// it takes: a raise keeps the coins of the spend it replaces, and a
		// request whose spend never went out keeps the coins of its action. A
		// split it takes no coin of is left as it is. Once a split is replaced
		// its coins are those of the replacement, and the selection is made
		// again.
		for (const txid of new Set(
			selected
				.filter((coin) => (listed.get(key(coin.utxo))?.height ?? 0) <= 0)
				.map((coin) => coin.utxo.tx_hash.toLowerCase())
		))
			if ((await this.raiseIfDue(txid, splitAt, opts)) !== txid)
				return this.selectLocked(
					targetFeeSats,
					feeratePerKw,
					opts,
					sent,
					prefer
				);
		if (sum > cap)
			throw new FixedOutputFeeError(
				'FEE_ACTION_CAP_EXHAUSTED',
				'operator',
				'Fixed-output action fee cap exhausted'
			);
		const next = copy(this.journal),
			taken = new Set(selected.map((coin) => key(coin.utxo)));
		const before = this.held(next.actions[id]);
		next.actions[id].inputs = selected;
		if (gone.length) next.actions[id].gone = gone;
		// A moved record whose coin the action neither holds nor let go of is
		// out of date: a release that does not keep the record moved the coin
		// since. It is dropped with the row's next write.
		const moved = next.actions[id].moved;
		if (moved) {
			for (const [was, is] of Object.entries(moved))
				if (!this.has(next.actions[id], is)) delete moved[was];
			if (!Object.keys(moved).length) delete next.actions[id].moved;
		}
		// An action that takes more than it held, as a raise does, needs
		// room in the budget for the difference.
		const more = this.held(next.actions[id]) - before;
		if (more > 0n) this.assertRoom(more);
		if (next.coins)
			next.coins = next.coins.filter((coin) => !taken.has(key(coin.utxo)));
		this.save(next);
		const inputs: ISpliceWalletInput[] = [];
		for (const coin of selected) {
			// A free fee coin leaves the pool's tag for the action's own.
			if (frozen.get(key(coin.utxo)) === this.coinTag)
				await this.unfreeze(coin.utxo.tx_hash, coin.utxo.tx_pos, this.coinTag);
			await this.bounded('a fee coin pledge', () =>
				this.host.pledge(
					coin.utxo.tx_hash,
					coin.utxo.tx_pos,
					this.prefix + ':action:' + id
				)
			);
			const current = listed.get(key(coin.utxo));
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
