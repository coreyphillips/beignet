/**
 * The end on chain of an ordinary channel, reduced to digests (issue #2093):
 * open, payments each way, five HTLCs left in flight, and then either a force
 * close by one side or an old, revoked commitment of one side put on the
 * chain by somebody else. Both nodes follow the chain through their own
 * watcher until nothing is left to do: what each tracked, every transaction
 * each handed on to be published and in what order, and what the chain would
 * not take.
 *
 * Like ordinary-rounds, this runs against any source tree that offers the
 * engine below, under a counter in place of randomness, so the digests of
 * the previous release's source can be pinned and compared with this one's.
 */

import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import type {
	ChannelManager,
	IChannelManagerConfig
} from '../../../src/lightning/channel/channel-manager';
import type {
	ChainWatcher,
	IChainWatcherConfig
} from '../../../src/lightning/chain/chain-watcher';
import type { ChainMonitor } from '../../../src/lightning/chain/chain-monitor';
import type { IChannelState } from '../../../src/lightning/channel/channel-state';
import type { IFundingProvider } from '../../../src/lightning/node/types';
import { ecc } from '../../../src/utils/ecc';
import type { IOrdinaryRoundsEngine, OrdinaryKind } from './ordinary-rounds';
import { AsyncLocalStorage } from 'async_hooks';
import { TestChain, TestChainBackend } from './auxiliary-chain';

export interface IOrdinaryForceCloseEngine extends IOrdinaryRoundsEngine {
	ChainWatcher: new (config: IChainWatcherConfig) => ChainWatcher;
	serializeChainMonitorState(
		state: ReturnType<ChainMonitor['getFullState']>
	): unknown;
	createFundingScript(local: Buffer, remote: Buffer): { p2wshOutput: Buffer };
	createTaprootFundingScript(
		local: Buffer,
		remote: Buffer
	): { p2trOutput: Buffer };
	privAt(seed: Buffer, index: number): Buffer;
}

/** What one node did about the end of the channel. */
export interface IOrdinaryForceCloseSide {
	/** The first eight characters of each transaction id it published, in order. */
	order: string;
	/** A digest of the bytes of those transactions, in that order. */
	bytes: string;
	/** What the chain would not take: the transaction and the reason. */
	refused: string[];
	/** Kind and status of every output it tracked, once the commitment confirmed. */
	trackedAtClose: string;
	/** A digest of those rows. */
	rowsAtClose: string;
	/** The same at the end. */
	trackedAtEnd: string;
	rowsAtEnd: string;
	/** Whether its monitor says everything is resolved. */
	resolved: boolean;
}

export interface IOrdinaryForceCloseDigests {
	errors: string[];
	alice: IOrdinaryForceCloseSide;
	bob: IOrdinaryForceCloseSide;
	/** Every monitor row either node stored, in order. */
	monitorRowsStored: number;
	monitorRows: string;
	/** The height the chain ended at. */
	height: number;
}

const sha = (value: Buffer | string): Buffer =>
	crypto.createHash('sha256').update(value).digest();

/** JSON with every bigint, Buffer, Map and undefined member spelled out. */
function stable(value: unknown): string {
	return JSON.stringify(value, (_key, item: unknown) => {
		if (item === undefined) return '(undefined)';
		if (typeof item === 'bigint') return `${item}n`;
		if (item instanceof Map) return { map: [...item] };
		if (item instanceof Set) return { set: [...item] };
		if (item instanceof Uint8Array) return Buffer.from(item).toString('hex');
		if (
			item &&
			typeof item === 'object' &&
			(item as { type?: unknown }).type === 'Buffer' &&
			Array.isArray((item as { data?: unknown }).data)
		) {
			return Buffer.from((item as { data: number[] }).data).toString('hex');
		}
		return item;
	});
}

const settle = async (): Promise<void> => {
	for (let turn = 0; turn < 6; turn++) {
		await new Promise<void>((resolve) => setImmediate(resolve));
	}
};

/**
 * After the close, block by block past every HTLC expiry, and then in
 * strides past two CSV delays and the depth at which an output is final.
 */
const SINGLE_BLOCKS_AFTER_CLOSE = 64;
const STRIDES_AFTER_CLOSE = 23;
const STRIDE = 12;

/** Coins a node's wallet holds to pay the fee of a transaction that has none. */
const FEE_COINS = 48;
const FEE_COIN_VALUE = 50_000;

/**
 * The least a wallet has to be for a channel manager to attach a fee: P2WPKH
 * coins of one key, on the chain, handed out one at a time, the first that
 * nothing has spent.
 */
function feeWallet(chain: TestChain, label: string): IFundingProvider {
	const key = sha(`ordinary force close fee key ${label}`);
	const pubkey = Buffer.from(ecc.pointFromScalar(key, true)!);
	const script = bitcoin.payments.p2wpkh({ pubkey }).output!;
	const coins = new bitcoin.Transaction();
	coins.version = 2;
	coins.addInput(sha(`ordinary force close fee coins ${label}`), 0);
	for (let index = 0; index < FEE_COINS; index++) {
		coins.addOutput(script, FEE_COIN_VALUE);
	}
	chain.seed(coins);
	const txid = coins.getId();
	const prevTx = coins.toBuffer();
	const wallet = {
		selectFeeBumpInputs: async () => {
			let index = 0;
			while (index < FEE_COINS && chain.spender(txid, index)) index++;
			if (index === FEE_COINS) throw new Error('the fee wallet is empty');
			return {
				inputs: [
					{
						prevTx,
						prevOutputIndex: index,
						value: BigInt(FEE_COIN_VALUE),
						sequence: 0xfffffffd,
						confirmed: true,
						signWitness: (
							tx: bitcoin.Transaction,
							inputIndex: number,
							value: bigint
						): Buffer[] => {
							const hashType = bitcoin.Transaction.SIGHASH_ALL;
							const digest = tx.hashForWitnessV0(
								inputIndex,
								bitcoin.payments.p2pkh({ pubkey }).output!,
								Number(value),
								hashType
							);
							return [
								bitcoin.script.signature.encode(
									Buffer.from(ecc.sign(digest, key)),
									hashType
								),
								pubkey
							];
						}
					}
				],
				changeScript: script
			};
		}
	};
	return wallet as unknown as IFundingProvider;
}

/**
 * Marks what a scenario itself runs, through every await and callback of
 * it, so that the counter in place of randomness serves the scenario alone.
 */
const scenarioScope = new AsyncLocalStorage<object>();

export function ordinaryForceClose(
	engine: IOrdinaryForceCloseEngine,
	kind: OrdinaryKind,
	scenario: 'current' | 'revoked',
	actor: 'alice' | 'bob',
	extraConfig: Partial<IChannelManagerConfig> = {}
): Promise<IOrdinaryForceCloseDigests> {
	const scope = {};
	return scenarioScope.run(scope, () =>
		runOrdinaryForceClose(scope, engine, kind, scenario, actor, extraConfig)
	);
}

async function runOrdinaryForceClose(
	scope: object,
	engine: IOrdinaryForceCloseEngine,
	kind: OrdinaryKind,
	scenario: 'current' | 'revoked',
	actor: 'alice' | 'bob',
	extraConfig: Partial<IChannelManagerConfig>
): Promise<IOrdinaryForceCloseDigests> {
	const realRandomBytes = crypto.randomBytes;
	engine.randomBytes(1);
	let counter = 0;
	(crypto as unknown as { randomBytes: unknown }).randomBytes = (
		size: number,
		...rest: unknown[]
	): Buffer => {
		// A draw by anything else in the process, such as a timer another
		// test file left behind, gets real randomness and does not move the
		// counter: the scenario's draws depend on the scenario alone.
		if (scenarioScope.getStore() !== scope) {
			return (
				realRandomBytes as unknown as (
					size: number,
					...rest: unknown[]
				) => Buffer
			)(size, ...rest);
		}
		const out = Buffer.alloc(size);
		const n = counter++;
		for (let i = 0; i < size; i += 32) {
			sha(`ordinary-force-close:${kind}:${n}:${i}`).copy(out, i);
		}
		return out;
	};
	const chain = new TestChain();
	// The scripts of the channels older than taproot are not run here: the
	// point of this file is that the bytes are the ones of the last release.
	chain.witnessScriptsOnTrust = kind !== 'taproot';
	const backends = {
		alice: new TestChainBackend(chain),
		bob: new TestChainBackend(chain)
	};
	const watchers: ChainWatcher[] = [];
	try {
		const errors: string[] = [];
		const monitorRows: string[] = [];
		const config = (name: 'alice' | 'bob'): IChannelManagerConfig => {
			const seed = engine.seedFor(name === 'alice' ? 4300 : 4301);
			return {
				...engine.configOf(seed, kind === 'taproot' && name === 'alice'),
				...(kind === 'anchors' ? { preferAnchors: true } : {}),
				revocationBasepointSecret: engine.privAt(seed, 1),
				paymentBasepointSecret: engine.privAt(seed, 2),
				delayedPaymentBasepointSecret: engine.privAt(seed, 3),
				...extraConfig
			};
		};
		const configs = { alice: config('alice'), bob: config('bob') };
		const managers = {
			alice: new engine.ChannelManager(configs.alice),
			bob: new engine.ChannelManager(configs.bob)
		};
		const pubkeys = {
			alice: configs.alice.localBasepoints.fundingPubkey,
			bob: configs.bob.localBasepoints.fundingPubkey
		};
		const destinations = {
			alice: Buffer.concat([
				Buffer.from('0014', 'hex'),
				Buffer.alloc(20, 0x42)
			]),
			bob: Buffer.concat([Buffer.from('0014', 'hex'), Buffer.alloc(20, 0x43)])
		};
		const other = (name: 'alice' | 'bob'): 'alice' | 'bob' =>
			name === 'alice' ? 'bob' : 'alice';
		for (const name of ['alice', 'bob'] as const) {
			const source = managers[name];
			const target = managers[other(name)];
			const sourcePubkey = pubkeys[name].toString('hex');
			const targetPubkey = pubkeys[other(name)].toString('hex');
			source.setFundingProvider(feeWallet(chain, name));
			source.on('error', (_id: unknown, message: unknown) => {
				errors.push(`${name}: ${String(message)}`);
			});
			source.on(
				'message:outbound',
				(peer: string, type: number, payload: Buffer) => {
					if (peer === targetPubkey) {
						target.handleMessage(sourcePubkey, type, payload);
					}
				}
			);
			source.on('monitor:updated', (_id: string, monitor: ChainMonitor) => {
				monitorRows.push(
					`${name}:${stable(
						engine.serializeChainMonitorState(monitor.getFullState())
					)}`
				);
			});
			const watcher = new engine.ChainWatcher({
				backend: backends[name],
				channelManager: source,
				destinationScript: destinations[name],
				getSweepFeeRatePerVbyte: () => 10
			});
			watcher.on('error', (error: Error) => {
				errors.push(`${name} watcher: ${error.message}`);
			});
			// What a node does when its watcher is asked to watch an output.
			watcher.on(
				'watch:output:requested',
				(txid: string, outputIndex: number) => {
					watcher.watchOutputByTxid(txid, outputIndex).catch((error: Error) => {
						errors.push(`${name} watch: ${error.message}`);
					});
				}
			);
			watchers.push(watcher);
			await watcher.start();
		}
		const { alice, bob } = managers;

		// One node hears of each thing the chain does after the other, so
		// that the order in which the two act is the same on any source.
		const step = async (act: () => void): Promise<void> => {
			backends.bob.hold();
			try {
				act();
				await settle();
			} finally {
				backends.bob.release();
			}
			await settle();
		};
		const must = (
			what: string,
			result: { ok: boolean; error?: string }
		): void => {
			if (!result.ok) {
				throw new Error(
					`${kind}: ${what} failed: ${result.error ?? ''} ${errors.join('; ')}`
				);
			}
		};

		// Open, with a push so that both sides can pay, on a funding
		// transaction that exists.
		const channel = alice.openChannel(
			pubkeys.bob.toString('hex'),
			3_000_000n,
			1_000_000_000n
		);
		const state = channel.getFullState();
		const taproot = engine.isTaprootChannel(state.channelType);
		const funding = new bitcoin.Transaction();
		funding.version = 2;
		funding.addInput(sha(`ordinary force close coin ${kind}`), 0);
		funding.addOutput(
			taproot
				? engine.createTaprootFundingScript(pubkeys.alice, pubkeys.bob)
						.p2trOutput
				: engine.createFundingScript(pubkeys.alice, pubkeys.bob).p2wshOutput,
			3_000_000
		);
		const fundingTxid = Buffer.from(funding.getHash());
		let signature: Buffer = Buffer.alloc(64, 1);
		if (!taproot) {
			channel.setFundingOutpoint(fundingTxid, 0);
			signature = engine.signRemoteCommitment(
				state as IChannelState,
				channel.getSigner()!,
				state.remoteCurrentPerCommitmentPoint!
			).signature;
		}
		const id = alice.createFunding(channel, fundingTxid, 0, signature);
		if (!id) throw new Error(`${kind}: funding failed: ${errors.join('; ')}`);
		await step(() => chain.seed(funding));
		await step(() => chain.advance(6));

		const preimage = (label: string): Buffer =>
			sha(`ordinary force close ${label}`);
		const add = (
			from: ChannelManager,
			label: string,
			amountMsat: bigint,
			cltv: number
		): void =>
			must(
				`add ${label}`,
				from.addHtlc(
					id,
					amountMsat,
					sha(preimage(label)),
					cltv,
					Buffer.alloc(1366, cltv % 251)
				)
			);
		const tip = chain.height;
		add(alice, 'a0', 60_000_000n, tip + 40);
		add(bob, 'b0', 30_000_000n, tip + 41);
		must('fulfil a0', bob.fulfillHtlc(id, 0n, preimage('a0')));
		must('fulfil b0', alice.fulfillHtlc(id, 0n, preimage('b0')));
		// Five stay in flight: one each way whose preimage the payee holds,
		// one each way that runs out, and one too small to have an output.
		add(alice, 'a1', 45_000_000n, tip + 42);
		add(alice, 'a2', 600_000n, tip + 43);
		add(alice, 'a3', 20_000_000n, tip + 44);
		add(bob, 'b1', 25_000_000n, tip + 45);
		add(bob, 'b2', 22_000_000n, tip + 46);

		let revoked: bitcoin.Transaction | undefined;
		if (scenario === 'revoked') {
			const old = managers[actor].getChannel(id)!;
			const plan = old.prepareForceClose(old.getSigner()!);
			if (!plan.ok) {
				throw new Error(`${kind}: no commitment to keep: ${plan.error}`);
			}
			revoked = bitcoin.Transaction.fromBuffer(plan.commitmentTx);
		}
		// One more payment, there and settled: the commitments above are
		// revoked on both sides.
		add(alice, 'a4', 15_000_000n, tip + 47);
		must('fulfil a4', bob.fulfillHtlc(id, 4n, preimage('a4')));
		bob.recordPreimage(sha(preimage('a1')), preimage('a1'));
		alice.recordPreimage(sha(preimage('b2')), preimage('b2'));
		if (errors.length > 0) {
			throw new Error(`${kind}: ${errors.join('; ')}`);
		}

		if (revoked) {
			const published = revoked;
			await step(() => {
				chain.admit(published);
			});
		} else {
			await step(() =>
				must(
					'force close',
					managers[actor].forceClose(id, destinations[actor], 10)
				)
			);
		}
		await step(() => chain.mine());
		const tracked = (
			name: 'alice' | 'bob'
		): { summary: string; rows: string } => {
			const outputs = managers[name].getMonitor(id)?.getTrackedOutputs() ?? [];
			return {
				summary: outputs
					.map((output) => `${output.outputType}:${output.status}`)
					.join(' '),
				rows: sha(stable(outputs)).toString('hex')
			};
		};
		const atClose = { alice: tracked('alice'), bob: tracked('bob') };
		for (let block = 0; block < SINGLE_BLOCKS_AFTER_CLOSE; block++) {
			await step(() => chain.mine());
		}
		for (let stride = 0; stride < STRIDES_AFTER_CLOSE; stride++) {
			await step(() => chain.advance(STRIDE));
		}
		const side = (name: 'alice' | 'bob'): IOrdinaryForceCloseSide => {
			const end = tracked(name);
			return {
				order: backends[name].published
					.map((hex) => bitcoin.Transaction.fromHex(hex).getId().slice(0, 8))
					.join(' '),
				bytes: sha(backends[name].published.join('\n')).toString('hex'),
				refused: backends[name].refused.map(
					(entry) => `${entry.txid.slice(0, 8)}: ${entry.reason}`
				),
				trackedAtClose: atClose[name].summary,
				rowsAtClose: atClose[name].rows,
				trackedAtEnd: end.summary,
				rowsAtEnd: end.rows,
				resolved: managers[name].getMonitor(id)?.isFullyResolved() ?? false
			};
		};
		return {
			errors,
			alice: side('alice'),
			bob: side('bob'),
			monitorRowsStored: monitorRows.length,
			monitorRows: sha(monitorRows.join('\n')).toString('hex'),
			height: chain.height
		};
	} finally {
		for (const watcher of watchers) watcher.stop();
		backends.alice.close();
		backends.bob.close();
		(crypto as unknown as { randomBytes: unknown }).randomBytes =
			realRandomBytes;
	}
}
