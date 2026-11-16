/**
 * A chain small enough to read, for the asset channel tests (issue #2093).
 *
 * It keeps every output it has seen, a mempool and blocks, and judges a
 * transaction the way a node would for the spends these tests make: every
 * input spends an output that exists and is unspent (or is replaced by a
 * transaction that pays more), relative and absolute lock times have
 * matured, the outputs do not exceed the inputs, the fee meets the minimum
 * relay rate and no output is dust. A taproot key spend has to carry a
 * BIP 340 signature of the key in the spent output; a taproot script spend
 * has to prove its leaf against that key and satisfy the leaf's script,
 * which is run here; a P2WPKH spend has to carry the key's signature.
 *
 * The keys are read from the chain, never from a channel's state, so a
 * transaction signed under another key than the one its output committed
 * to is refused here as it would be by the network.
 *
 * TestChainBackend puts a node on this chain through the same interface an
 * Electrum server is reached through, so a node finds confirmations and
 * spends, and publishes its transactions, as it does in production.
 */

import * as bitcoin from 'bitcoinjs-lib';
import { ecc } from '../../../src/utils/ecc';
import type { IChainBackend } from '../../../src/lightning/chain/chain-watcher';

bitcoin.initEccLib(ecc);

export interface IChainOutput {
	script: Buffer;
	value: number;
}

interface IStoredOutput extends IChainOutput {
	/** The height of the block that confirmed it; 0 while in the mempool. */
	height: number;
}

/** The smallest value a node relays for an output of this script. */
export function relayDustLimit(script: Buffer): number {
	if (script.length > 0 && script[0] === 0x6a) return 0;
	if (script.length === 22 && script[0] === 0x00) return 294;
	if (script.length === 34 && (script[0] === 0x00 || script[0] === 0x51)) {
		return 330;
	}
	if (script.length === 23) return 540;
	return 546;
}

const isTaprootOutput = (script: Buffer): boolean =>
	script.length === 34 && script[0] === 0x51 && script[1] === 0x20;

const isP2wpkhOutput = (script: Buffer): boolean =>
	script.length === 22 && script[0] === 0x00 && script[1] === 0x14;

/** The script hash an Electrum server indexes a script under. */
export function electrumScriptHash(script: Buffer): string {
	return Buffer.from(bitcoin.crypto.sha256(script)).reverse().toString('hex');
}

/** How a spend this chain does not judge by itself is judged, by input. */
export type SpendJudge = (
	tx: bitcoin.Transaction,
	inputIndex: number,
	spent: IChainOutput[]
) => void;

const OPS = bitcoin.opcodes;

const truthy = (item: Buffer): boolean =>
	item.some(
		(byte, index) => byte !== 0 && !(index === item.length - 1 && byte === 0x80)
	);

/** Run a tapscript leaf over a witness stack. Throws when it is not satisfied. */
function runTapscript(
	script: Buffer,
	initial: Buffer[],
	check: {
		signature(pubkey: Buffer, signature: Buffer): boolean;
		sequence(lock: number): void;
		locktime(lock: number): void;
	}
): void {
	const ops = bitcoin.script.decompile(script);
	if (!ops) throw new Error('a leaf script that cannot be read');
	const stack = initial.map((item) => Buffer.from(item));
	const executing: boolean[] = [];
	const pop = (): Buffer => {
		const item = stack.pop();
		if (!item) throw new Error('the leaf script ran out of stack');
		return item;
	};
	for (const op of ops) {
		const live = executing.every(Boolean);
		if (Buffer.isBuffer(op)) {
			if (live) stack.push(Buffer.from(op));
			continue;
		}
		if (op === OPS.OP_IF || op === OPS.OP_NOTIF) {
			let branch = false;
			if (live) {
				const top = pop();
				if (top.length > 1 || (top.length === 1 && top[0] !== 1)) {
					throw new Error('a branch argument that is not minimal');
				}
				branch = op === OPS.OP_IF ? truthy(top) : !truthy(top);
			}
			executing.push(branch);
			continue;
		}
		if (op === OPS.OP_ELSE) {
			if (!executing.length) throw new Error('OP_ELSE without OP_IF');
			executing[executing.length - 1] = !executing[executing.length - 1];
			continue;
		}
		if (op === OPS.OP_ENDIF) {
			if (!executing.length) throw new Error('OP_ENDIF without OP_IF');
			executing.pop();
			continue;
		}
		if (!live) continue;
		if (op === OPS.OP_0) {
			stack.push(Buffer.alloc(0));
		} else if (op >= OPS.OP_1 && op <= OPS.OP_16) {
			stack.push(Buffer.from([op - OPS.OP_1 + 1]));
		} else if (op === OPS.OP_VERIFY) {
			if (!truthy(pop())) throw new Error('OP_VERIFY failed');
		} else if (op === OPS.OP_DROP) {
			pop();
		} else if (op === OPS.OP_DUP) {
			const top = pop();
			stack.push(top, Buffer.from(top));
		} else if (op === OPS.OP_SWAP) {
			const a = pop();
			const b = pop();
			stack.push(a, b);
		} else if (op === OPS.OP_SIZE) {
			const top = pop();
			stack.push(top, bitcoin.script.number.encode(top.length));
		} else if (op === OPS.OP_EQUAL || op === OPS.OP_EQUALVERIFY) {
			const equal = pop().equals(pop());
			if (op === OPS.OP_EQUAL) {
				stack.push(equal ? Buffer.from([1]) : Buffer.alloc(0));
			} else if (!equal) throw new Error('OP_EQUALVERIFY failed');
		} else if (op === OPS.OP_HASH160) {
			stack.push(bitcoin.crypto.hash160(pop()));
		} else if (op === OPS.OP_SHA256) {
			stack.push(bitcoin.crypto.sha256(pop()));
		} else if (op === OPS.OP_RIPEMD160) {
			stack.push(bitcoin.crypto.ripemd160(pop()));
		} else if (op === OPS.OP_CHECKSIG || op === OPS.OP_CHECKSIGVERIFY) {
			const pubkey = pop();
			const signature = pop();
			const valid = check.signature(pubkey, signature);
			if (op === OPS.OP_CHECKSIG) {
				stack.push(valid ? Buffer.from([1]) : Buffer.alloc(0));
			} else if (!valid) throw new Error('OP_CHECKSIGVERIFY failed');
		} else if (op === OPS.OP_CHECKSEQUENCEVERIFY) {
			const top = stack[stack.length - 1];
			if (!top) throw new Error('the leaf script ran out of stack');
			check.sequence(bitcoin.script.number.decode(top, 5));
		} else if (op === OPS.OP_CHECKLOCKTIMEVERIFY) {
			const top = stack[stack.length - 1];
			if (!top) throw new Error('the leaf script ran out of stack');
			check.locktime(bitcoin.script.number.decode(top, 5));
		} else {
			throw new Error(`opcode ${op} is not one this chain runs`);
		}
	}
	if (executing.length) throw new Error('OP_IF without OP_ENDIF');
	if (stack.length !== 1 || !truthy(stack[0])) {
		throw new Error('the leaf script did not end on a single true');
	}
}

export class TestChain {
	private readonly outputs = new Map<string, IStoredOutput>();
	private readonly spentBy = new Map<string, string>();
	private readonly byScript = new Map<string, Set<string>>();
	private readonly backends = new Set<TestChainBackend>();
	/** Every transaction this chain confirmed, by id, with its height. */
	readonly confirmed = new Map<
		string,
		{ tx: bitcoin.Transaction; height: number }
	>();
	/** Every transaction waiting for a block, by id, with what it pays. */
	readonly mempool = new Map<
		string,
		{ tx: bitcoin.Transaction; fee: number; vsize: number }
	>();
	height = 100;
	/**
	 * A spend of a P2WSH output is taken on the hash of its witness script
	 * alone, its script not run: for the channels older than taproot, whose
	 * scripts this chain does not run. Off unless a test turns it on.
	 */
	witnessScriptsOnTrust = false;

	private static key(txid: string, vout: number): string {
		return `${txid}:${vout}`;
	}

	private static outpoint(input: { hash: Buffer; index: number }): string {
		return TestChain.key(
			Buffer.from(input.hash).reverse().toString('hex'),
			input.index
		);
	}

	/** @internal */
	attach(backend: TestChainBackend): void {
		this.backends.add(backend);
	}

	/** @internal */
	detach(backend: TestChainBackend): void {
		this.backends.delete(backend);
	}

	private index(tx: bitcoin.Transaction, height: number): string[] {
		const txid = tx.getId();
		const touched = new Set<string>();
		for (const input of tx.ins) {
			const spent = this.outputs.get(TestChain.outpoint(input));
			if (spent) touched.add(electrumScriptHash(spent.script));
		}
		tx.outs.forEach((out, vout) => {
			this.outputs.set(TestChain.key(txid, vout), {
				script: Buffer.from(out.script),
				value: out.value,
				height
			});
			touched.add(electrumScriptHash(out.script));
		});
		for (const hash of touched) {
			let known = this.byScript.get(hash);
			if (!known) this.byScript.set(hash, (known = new Set()));
			known.add(txid);
		}
		return [...touched];
	}

	private announce(scriptHashes: Iterable<string>, block: boolean): void {
		const hashes = [...new Set(scriptHashes)];
		for (const backend of this.backends) {
			if (block) backend.announceBlock(this.height);
			for (const hash of hashes) backend.announceScript(hash);
		}
	}

	/**
	 * Put a transaction's outputs on the chain, confirmed, without judging
	 * its inputs: a funding transaction, whose inputs a test invents.
	 */
	seed(tx: bitcoin.Transaction): void {
		const touched = this.index(tx, this.height);
		this.confirmed.set(tx.getId(), { tx, height: this.height });
		this.announce(touched, false);
	}

	/** The unspent output at an outpoint, or undefined. */
	output(txid: string, vout: number): IChainOutput | undefined {
		const key = TestChain.key(txid, vout);
		const output = this.outputs.get(key);
		if (!output || this.spentBy.has(key)) return undefined;
		return { script: output.script, value: output.value };
	}

	/** The id of the transaction that spends an outpoint, or undefined. */
	spender(txid: string, vout: number): string | undefined {
		return this.spentBy.get(TestChain.key(txid, vout));
	}

	/** A transaction in a block or in the mempool, or undefined. */
	transaction(txid: string): bitcoin.Transaction | undefined {
		return this.confirmed.get(txid)?.tx ?? this.mempool.get(txid)?.tx;
	}

	/** What an Electrum server answers for a script hash. */
	history(scriptHash: string): Array<{ txid: string; height: number }> {
		const rows = [...(this.byScript.get(scriptHash) ?? [])].map((txid) => ({
			txid,
			height: this.confirmed.get(txid)?.height ?? 0
		}));
		const settled = rows
			.filter((row) => row.height > 0)
			.sort((a, b) => a.height - b.height);
		return [...settled, ...rows.filter((row) => row.height === 0)];
	}

	/** The mempool transactions a transaction would replace, with their descendants. */
	private conflicts(tx: bitcoin.Transaction): string[] {
		const found = new Set<string>();
		const visit = (txid: string): void => {
			const entry = this.mempool.get(txid);
			if (!entry || found.has(txid)) return;
			found.add(txid);
			entry.tx.outs.forEach((_out, vout) => {
				const child = this.spentBy.get(TestChain.key(txid, vout));
				if (child) visit(child);
			});
		};
		for (const input of tx.ins) {
			const by = this.spentBy.get(TestChain.outpoint(input));
			if (by) visit(by);
		}
		return [...found];
	}

	/**
	 * Judge a transaction and say what it pays. Throws with the reason it
	 * would not be relayed or mined. `judge` replaces this chain's own
	 * judgement of every input that is not a taproot key spend.
	 */
	accept(
		tx: bitcoin.Transaction,
		judge?: SpendJudge
	): { fee: number; vsize: number } {
		if (tx.ins.length === 0) throw new Error('a transaction needs an input');
		const replaced = new Set(this.conflicts(tx));
		const spent = tx.ins.map((input) => {
			const point = TestChain.outpoint(input);
			const output = this.outputs.get(point);
			const by = this.spentBy.get(point);
			if (!output || replaced.has(point.split(':')[0])) {
				throw new Error(`input ${point} does not exist`);
			}
			if (by && !replaced.has(by)) {
				throw new Error(`input ${point} is already spent by ${by}`);
			}
			return output;
		});
		if (
			new Set(tx.ins.map((input) => TestChain.outpoint(input))).size !==
			tx.ins.length
		) {
			throw new Error('a transaction spends an outpoint twice');
		}
		const paidIn = spent.reduce((sum, output) => sum + output.value, 0);
		const paidOut = tx.outs.reduce((sum, output) => sum + output.value, 0);
		if (paidOut > paidIn) throw new Error('outputs exceed inputs');
		const fee = paidIn - paidOut;
		const vsize = Math.ceil(tx.weight() / 4);
		if (fee < vsize) {
			throw new Error(
				`fee ${fee} is below the minimum relay fee for ${vsize} vB`
			);
		}
		if (replaced.size) {
			const old = [...replaced].map((txid) => this.mempool.get(txid)!);
			const oldFee = old.reduce((sum, entry) => sum + entry.fee, 0);
			if (
				fee < oldFee + vsize ||
				old.some((entry) => fee * entry.vsize <= entry.fee * vsize)
			) {
				throw new Error(
					`a replacement paying ${fee} for ${vsize} vB does not pay enough over ${oldFee}`
				);
			}
		}
		for (const [index, out] of tx.outs.entries()) {
			if (out.value < relayDustLimit(out.script)) {
				throw new Error(`output ${index} of ${out.value} sat is dust`);
			}
		}
		const final = tx.ins.every((input) => input.sequence === 0xffffffff);
		if (!final && tx.locktime > 0 && tx.locktime < 500_000_000) {
			if (tx.locktime > this.height) {
				throw new Error(
					`lock time ${tx.locktime} has not been reached at height ${this.height}`
				);
			}
		}
		tx.ins.forEach((input, index) => {
			const output = spent[index];
			if (tx.version >= 2 && (input.sequence & 0x80000000) === 0) {
				if (input.sequence & 0x00400000) {
					throw new Error(`input ${index} has a relative lock in time`);
				}
				const lock = input.sequence & 0xffff;
				if (lock > 0 && output.height === 0) {
					throw new Error(
						`input ${index} waits ${lock} blocks on an unconfirmed output`
					);
				}
				if (lock > 0 && this.height + 1 < output.height + lock) {
					throw new Error(
						`input ${index} has not waited its ${lock} blocks (confirmed at ${output.height}, now ${this.height})`
					);
				}
			}
			const keySpend =
				isTaprootOutput(output.script) && input.witness.length === 1;
			if (!keySpend) {
				if (judge) judge(tx, index, spent);
				else this.judgeScriptSpend(tx, index, spent);
				return;
			}
			const signature = input.witness[0];
			if (signature.length !== 64 && signature.length !== 65) {
				throw new Error(`input ${index} carries no schnorr signature`);
			}
			const hashType =
				signature.length === 65
					? signature[64]
					: bitcoin.Transaction.SIGHASH_DEFAULT;
			const sighash = tx.hashForWitnessV1(
				index,
				spent.map((each) => each.script),
				spent.map((each) => each.value),
				hashType
			);
			if (
				!ecc.verifySchnorr(
					sighash,
					output.script.subarray(2),
					signature.subarray(0, 64)
				)
			) {
				throw new Error(
					`input ${index} is not signed by the key of the output it spends`
				);
			}
		});
		return { fee, vsize };
	}

	/** This chain's own judgement of a spend that is not a taproot key spend. */
	private judgeScriptSpend(
		tx: bitcoin.Transaction,
		index: number,
		spent: IStoredOutput[]
	): void {
		const input = tx.ins[index];
		const output = spent[index];
		if (
			this.witnessScriptsOnTrust &&
			output.script.length === 34 &&
			output.script[0] === 0x00 &&
			output.script[1] === 0x20
		) {
			const script = input.witness[input.witness.length - 1];
			if (
				!script ||
				input.script.length !== 0 ||
				!bitcoin.crypto.sha256(script).equals(output.script.subarray(2))
			) {
				throw new Error(`input ${index} does not show its witness script`);
			}
			return;
		}
		if (isP2wpkhOutput(output.script)) {
			if (input.witness.length !== 2 || input.script.length !== 0) {
				throw new Error(`input ${index} is not a P2WPKH spend`);
			}
			const [signature, pubkey] = input.witness;
			if (!bitcoin.crypto.hash160(pubkey).equals(output.script.subarray(2))) {
				throw new Error(`input ${index} names another key than its output`);
			}
			const decoded = bitcoin.script.signature.decode(signature);
			const sighash = tx.hashForWitnessV0(
				index,
				bitcoin.payments.p2pkh({ pubkey }).output!,
				output.value,
				decoded.hashType
			);
			if (!ecc.verify(sighash, pubkey, decoded.signature)) {
				throw new Error(
					`input ${index} is not signed by the key of the output it spends`
				);
			}
			return;
		}
		if (!isTaprootOutput(output.script) || input.witness.length < 2) {
			throw new Error(`input ${index} is a spend this chain cannot judge`);
		}
		const control = input.witness[input.witness.length - 1];
		const script = input.witness[input.witness.length - 2];
		if (control.length < 33 || (control.length - 33) % 32 !== 0) {
			throw new Error(`input ${index} carries no control block`);
		}
		const leafVersion = control[0] & 0xfe;
		const leafHash = bitcoin.crypto.taggedHash(
			'TapLeaf',
			Buffer.concat([
				Buffer.from([leafVersion]),
				bitcoin.script.number.encode(script.length).length === 1 &&
				script.length < 253
					? Buffer.from([script.length])
					: Buffer.from([0xfd, script.length & 0xff, script.length >> 8]),
				script
			])
		);
		let node = leafHash;
		for (let at = 33; at < control.length; at += 32) {
			const sibling = control.subarray(at, at + 32);
			node = bitcoin.crypto.taggedHash(
				'TapBranch',
				Buffer.compare(node, sibling) <= 0
					? Buffer.concat([node, sibling])
					: Buffer.concat([sibling, node])
			);
		}
		const internal = control.subarray(1, 33);
		const tweaked = ecc.xOnlyPointAddTweak(
			internal,
			bitcoin.crypto.taggedHash('TapTweak', Buffer.concat([internal, node]))
		);
		if (
			!tweaked ||
			!Buffer.from(tweaked.xOnlyPubkey).equals(output.script.subarray(2)) ||
			tweaked.parity !== (control[0] & 1)
		) {
			throw new Error(
				`input ${index} proves a leaf that the output it spends does not commit to`
			);
		}
		if (leafVersion !== 0xc0) {
			throw new Error(`input ${index} spends a leaf this chain cannot run`);
		}
		try {
			runTapscript(script, input.witness.slice(0, -2), {
				signature: (pubkey, signature) => {
					if (signature.length === 0) return false;
					if (pubkey.length !== 32) {
						throw new Error('a key that is not 32 bytes');
					}
					if (signature.length !== 64 && signature.length !== 65) {
						throw new Error('a signature that is not schnorr');
					}
					const hashType =
						signature.length === 65
							? signature[64]
							: bitcoin.Transaction.SIGHASH_DEFAULT;
					const sighash = tx.hashForWitnessV1(
						index,
						spent.map((each) => each.script),
						spent.map((each) => each.value),
						hashType,
						leafHash
					);
					if (!ecc.verifySchnorr(sighash, pubkey, signature.subarray(0, 64))) {
						throw new Error('a signature that does not verify');
					}
					return true;
				},
				sequence: (lock) => {
					if (
						tx.version < 2 ||
						(input.sequence & 0x80000000) !== 0 ||
						(input.sequence & 0xffff) < lock
					) {
						throw new Error(
							`a sequence below the ${lock} blocks the leaf asks`
						);
					}
				},
				locktime: (lock) => {
					if (input.sequence === 0xffffffff || tx.locktime < lock) {
						throw new Error(`a lock time below the ${lock} the leaf asks`);
					}
				}
			});
		} catch (error) {
			throw new Error(
				`input ${index} does not satisfy its leaf: ${(error as Error).message}`
			);
		}
	}

	/**
	 * Judge a transaction and take it into the mempool, in place of what it
	 * replaces. Its outputs can be spent at once by transactions that do not
	 * wait on a relative lock. Returns what it pays.
	 */
	admit(
		tx: bitcoin.Transaction,
		judge?: SpendJudge
	): { fee: number; vsize: number } {
		const txid = tx.getId();
		const known = this.mempool.get(txid);
		if (known) return { fee: known.fee, vsize: known.vsize };
		if (this.confirmed.has(txid)) {
			throw new Error('the transaction is already in a block');
		}
		const paid = this.accept(tx, judge);
		const touched: string[] = [];
		for (const old of this.conflicts(tx)) {
			const entry = this.mempool.get(old)!;
			this.mempool.delete(old);
			for (const input of entry.tx.ins) {
				const point = TestChain.outpoint(input);
				if (this.spentBy.get(point) === old) this.spentBy.delete(point);
				const output = this.outputs.get(point);
				if (output) touched.push(electrumScriptHash(output.script));
			}
			entry.tx.outs.forEach((out, vout) => {
				this.outputs.delete(TestChain.key(old, vout));
				const hash = electrumScriptHash(out.script);
				touched.push(hash);
			});
			for (const set of this.byScript.values()) set.delete(old);
		}
		touched.push(...this.index(tx, 0));
		for (const input of tx.ins) {
			this.spentBy.set(TestChain.outpoint(input), txid);
		}
		this.mempool.set(txid, { tx, ...paid });
		this.announce(touched, false);
		return paid;
	}

	/**
	 * Confirm the mempool in a new block and return its height. Given a
	 * transaction, it is judged and taken into the mempool first.
	 */
	mine(tx?: bitcoin.Transaction, judge?: SpendJudge): number {
		if (tx) this.admit(tx, judge);
		this.height += 1;
		const touched: string[] = [];
		for (const [txid, entry] of this.mempool) {
			this.confirmed.set(txid, { tx: entry.tx, height: this.height });
			for (const input of entry.tx.ins) {
				const output = this.outputs.get(TestChain.outpoint(input));
				if (output) touched.push(electrumScriptHash(output.script));
			}
			entry.tx.outs.forEach((out, vout) => {
				const output = this.outputs.get(TestChain.key(txid, vout));
				if (output) output.height = this.height;
				touched.push(electrumScriptHash(out.script));
			});
		}
		this.mempool.clear();
		this.announce(touched, true);
		return this.height;
	}

	/** Let `blocks` empty blocks pass, announcing only the last. */
	advance(blocks: number): number {
		if (blocks > 1) this.height += blocks - 1;
		return this.mine();
	}
}

/** One node's connection to a TestChain, as its Electrum server. */
export class TestChainBackend implements IChainBackend {
	/** Every transaction this node asked to have published, in order, as hex. */
	readonly published: string[] = [];
	/** The ones the chain would not take, with its reason. */
	readonly refused: Array<{ txid: string; reason: string }> = [];
	private readonly headers: Array<(height: number) => void> = [];
	private readonly scripts = new Map<string, Array<() => void>>();
	private held: Array<() => void> | undefined;

	constructor(readonly chain: TestChain) {
		chain.attach(this);
	}

	/** Stop hearing from the chain: the node this served is gone. */
	close(): void {
		this.chain.detach(this);
	}

	/**
	 * Keep what the chain announces from the node until `release`, so that a
	 * test can let two nodes hear of the same block one after the other.
	 */
	hold(): void {
		this.held ??= [];
	}

	/** Tell the node what the chain announced since `hold`, in order. */
	release(): void {
		const held = this.held ?? [];
		this.held = undefined;
		for (const tell of held) tell();
	}

	/** @internal */
	announceBlock(height: number): void {
		if (this.held) {
			this.held.push(() => this.announceBlock(height));
			return;
		}
		for (const heard of [...this.headers]) heard(height);
	}

	/** @internal */
	announceScript(scriptHash: string): void {
		if (this.held) {
			this.held.push(() => this.announceScript(scriptHash));
			return;
		}
		for (const heard of [...(this.scripts.get(scriptHash) ?? [])]) heard();
	}

	async subscribeToHeaders(
		onNewBlock: (height: number) => void
	): Promise<void> {
		this.headers.push(onNewBlock);
		onNewBlock(this.chain.height);
	}

	async subscribeToScriptHash(
		scriptHash: string,
		onChange: () => void
	): Promise<void> {
		const heard = this.scripts.get(scriptHash) ?? [];
		heard.push(onChange);
		this.scripts.set(scriptHash, heard);
	}

	async getScriptHashHistory(
		scriptHash: string
	): Promise<Array<{ txid: string; height: number }>> {
		return this.chain.history(scriptHash);
	}

	async getTransaction(txid: string): Promise<Buffer> {
		const tx = this.chain.transaction(txid);
		if (!tx) throw new Error('No such mempool or blockchain transaction');
		return tx.toBuffer();
	}

	async broadcastTransaction(rawTxHex: string): Promise<string> {
		this.published.push(rawTxHex);
		const tx = bitcoin.Transaction.fromHex(rawTxHex);
		const txid = tx.getId();
		if (this.chain.confirmed.has(txid)) return txid;
		try {
			this.chain.admit(tx);
		} catch (error) {
			this.refused.push({ txid, reason: (error as Error).message });
			throw error;
		}
		return txid;
	}

	async getTransactionMerkleProof(
		txid: string,
		height: number
	): Promise<{ blockHeight: number; txIndex: number }> {
		const entry = this.chain.confirmed.get(txid);
		if (!entry || entry.height !== height) {
			throw new Error('the transaction is not in that block');
		}
		const block = [...this.chain.confirmed.entries()]
			.filter(([, each]) => each.height === height)
			.map(([id]) => id);
		return { blockHeight: height, txIndex: block.indexOf(txid) + 1 };
	}
}
