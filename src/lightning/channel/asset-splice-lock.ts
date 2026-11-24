import { encodeSpliceLockedMessage } from '../message/splice';

export interface IAssetSpliceLockTerms {
	readonly channelId: string;
	readonly txid: string;
	readonly outputIndex: number;
	readonly finalDigest: string;
	readonly minimumDepth: number;
}
export interface IAssetSpliceAnchor {
	readonly txid: string;
	readonly blockHash: string;
	readonly confirmations: number;
}
type Transition =
	| { kind: 'peer' }
	| { kind: 'local'; blockHash: string }
	| { kind: 'adopt'; blockHash: string }
	| { kind: 'reconcile' };
export type IAssetSpliceLockEvent = Transition & {
	readonly terms: IAssetSpliceLockTerms;
};
interface ILockJournal {
	read(): readonly IAssetSpliceLockEvent[];
	/** Atomically append only if the journal still has expectedLength entries. */
	append(event: IAssetSpliceLockEvent, expectedLength: number): void;
}

const hash = /^[0-9a-f]{64}$/;
function sameTerms(
	a: IAssetSpliceLockTerms,
	b: IAssetSpliceLockTerms
): boolean {
	return (
		a.channelId === b.channelId &&
		a.txid === b.txid &&
		a.outputIndex === b.outputIndex &&
		a.finalDigest === b.finalDigest &&
		a.minimumDepth === b.minimumDepth
	);
}

/** One candidate. Inclusion and wallet proof verification are required on every restart. */
export class AssetSpliceLock {
	private readonly terms: IAssetSpliceLockTerms;
	private observation = 0;
	private verifiedBlock?: string;

	constructor(
		terms: IAssetSpliceLockTerms,
		private readonly journal: ILockJournal,
		private readonly verify: (
			terms: IAssetSpliceLockTerms,
			anchor: IAssetSpliceAnchor
		) => Promise<void>
	) {
		if (
			!hash.test(terms.channelId) ||
			!hash.test(terms.txid) ||
			!hash.test(terms.finalDigest) ||
			!Number.isSafeInteger(terms.outputIndex) ||
			terms.outputIndex < 0 ||
			terms.outputIndex > 0xffffffff ||
			!Number.isSafeInteger(terms.minimumDepth) ||
			terms.minimumDepth < 1
		)
			throw new Error('Invalid asset splice lock terms');
		this.terms = Object.freeze({ ...terms });
		this.history();
	}

	private history() {
		let peer = false,
			adopted = false,
			reconcile = false;
		let block: string | undefined;
		const events = this.journal.read();
		for (const e of events) {
			if (!sameTerms(e.terms, this.terms) || reconcile)
				throw new Error('Invalid asset splice lock journal');
			switch (e.kind) {
				case 'peer':
					if (peer) throw new Error('Duplicate peer splice lock');
					peer = true;
					break;
				case 'local':
					if (!hash.test(e.blockHash) || adopted || block === e.blockHash)
						throw new Error('Invalid local splice lock');
					block = e.blockHash;
					break;
				case 'adopt':
					if (!peer || !block || e.blockHash !== block || adopted)
						throw new Error('Invalid splice adoption');
					adopted = true;
					break;
				case 'reconcile':
					reconcile = true;
					break;
				default:
					throw new Error('Unknown asset splice lock event');
			}
		}
		return { peer, adopted, reconcile, block, length: events.length };
	}

	private write(event: Transition, expectedLength: number): void {
		this.journal.append({ ...event, terms: this.terms }, expectedLength);
	}

	private adopt(): void {
		const h = this.history();
		if (
			!h.reconcile &&
			!h.adopted &&
			h.peer &&
			h.block &&
			this.verifiedBlock === h.block
		)
			this.write({ kind: 'adopt', blockHash: h.block }, h.length);
	}

	async observe(anchor: IAssetSpliceAnchor | null): Promise<void> {
		const observation = ++this.observation;
		this.verifiedBlock = undefined;
		const h = this.history();
		if (h.reconcile) return;
		const confirmed =
			anchor &&
			anchor.txid === this.terms.txid &&
			hash.test(anchor.blockHash) &&
			Number.isSafeInteger(anchor.confirmations) &&
			anchor.confirmations >= this.terms.minimumDepth;
		if (h.adopted && (!confirmed || h.block !== anchor!.blockHash)) {
			this.write({ kind: 'reconcile' }, h.length);
			return;
		}
		if (!confirmed || !anchor) return;
		const sample = Object.freeze({ ...anchor });
		await this.verify(this.terms, sample);
		if (observation !== this.observation) return;
		const current = this.history();
		if (current.reconcile) return;
		if (current.adopted && current.block !== sample.blockHash) {
			this.write({ kind: 'reconcile' }, current.length);
			return;
		}
		if (current.block !== sample.blockHash)
			this.write(
				{ kind: 'local', blockHash: sample.blockHash },
				current.length
			);
		this.verifiedBlock = sample.blockHash;
		this.adopt();
	}

	/** A disconnect or a new chain lookup invalidates the previous block sample. */
	suspend(): void {
		++this.observation;
		this.verifiedBlock = undefined;
	}

	async peerLocked(txid: string): Promise<void> {
		const h = this.history();
		if (h.reconcile) return;
		if (txid !== this.terms.txid) {
			this.verifiedBlock = undefined;
			++this.observation;
			this.write({ kind: 'reconcile' }, h.length);
			return;
		}
		if (!h.peer) this.write({ kind: 'peer' }, h.length);
		this.adopt();
	}

	state() {
		const h = this.history();
		return {
			localLocked: h.block !== undefined,
			peerLocked: h.peer,
			adopted: h.adopted,
			needsReconciliation: h.reconcile
		};
	}

	outboundLock(): Buffer | undefined {
		const h = this.history();
		if (h.reconcile || !this.verifiedBlock || this.verifiedBlock !== h.block)
			return;
		return encodeSpliceLockedMessage({
			channelId: Buffer.from(this.terms.channelId, 'hex'),
			fundingTxid: Buffer.from(this.terms.txid, 'hex').reverse()
		});
	}
}
