/**
 * Asset channels on a chain (issue #2093): two hosts, each with its own
 * connection to a test chain and its own chain watcher, an asset channel
 * between them whose funding is in a block, and a provider that makes the
 * asset side of a sweep and remembers what it was asked.
 */

import assert from 'assert';
import {
	deserializeChainMonitorState,
	serializeChainMonitorState
} from '../../../src/lightning/storage/serialization';
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import * as bitcoin from 'bitcoinjs-lib';
import type {
	IAuxiliarySweepContext,
	IAuxiliarySweepResult,
	IChannelAuxiliaryProvider
} from '../../../src/lightning/channel/auxiliary';
import type {
	IAuxiliaryChannelConfig,
	IAuxiliaryFundingDescriptor
} from '../../../src/lightning/channel/auxiliary-funding';
import type { ITrackedOutput } from '../../../src/lightning/chain/types';
import { ChannelState } from '../../../src/lightning/channel/types';
import { PaymentStatus } from '../../../src/lightning/node/types';
import { createTaprootFundingScript } from '../../../src/lightning/script/funding-taproot';
import { ecc } from '../../../src/utils/ecc';
import { TestChain, TestChainBackend } from './auxiliary-chain';
import { assetHost, connectHosts, type IAssetHost } from './auxiliary-nodes';
import {
	ASSET_FUNDING_ROOT,
	amountRecord,
	hash,
	referenceProvider
} from './auxiliary-pair';
import { makeSeed } from './loopback-nodes';

import { chainWallet, type IChainWallet } from './auxiliary-fee-wallet';
import type { IFixedOutputFeePolicy } from '../../../src/lightning/wallet/fixed-output-fees';

export const settle = async (): Promise<void> => {
	for (let i = 0; i < 40; i++) {
		await new Promise<void>((resolve) => setImmediate(resolve));
	}
};

/** Where a node sweeps to when nothing of the sweep carries units. */
export const SWEEP_DESTINATION = Buffer.concat([
	Buffer.from('0014', 'hex'),
	Buffer.alloc(20, 5)
]);

/** Where the provider of these tests sends the units of a sweep. */
export const ASSET_SWEEP_SCRIPT = Buffer.concat([
	Buffer.from('5120', 'hex'),
	Buffer.from(ecc.xOnlyPointFromScalar(hash('asset sweep key')))
]);

/** One time the provider was asked for the asset side of a sweep. */
export interface ISweepCall {
	side: 'local' | 'remote';
	commitmentNumber: bigint;
	kinds: string[];
	/** The transaction as it was handed over, before any script was changed. */
	txid: string;
	destination: string;
}

export interface ISweepControl {
	/** A reason to refuse this call with, or undefined to answer it. */
	refuse?: (call: ISweepCall) => string | undefined;
	/** An answer to give in place of the right one. */
	answer?: (
		context: IAuxiliarySweepContext,
		right: IAuxiliarySweepResult
	) => unknown;
}

/** What the provider of these tests answers for a sweep it was asked about. */
export const sweepData = (call: ISweepCall): string =>
	`sweep:${call.side}:${call.commitmentNumber}:${call.kinds.join(',')}:`;

/**
 * The reference provider, and the asset side of a sweep: it has the host
 * sign once with the key of each input, checks the signature is by that
 * key, and sends the units to one script.
 */
export function sweepingProvider(
	calls: ISweepCall[],
	control: ISweepControl = {}
): IChannelAuxiliaryProvider {
	return {
		...referenceProvider(),
		prepareSweep(context): IAuxiliarySweepResult {
			const call: ISweepCall = {
				side: context.side,
				commitmentNumber: context.commitmentNumber,
				kinds: context.inputs.map((input) => input.kind),
				txid: context.transaction.getId(),
				destination: context.destinationScript.toString('hex')
			};
			calls.push(call);
			const refusal = control.refuse?.(call);
			if (refusal) throw new Error(refusal);
			const signatures = context.inputs.map((input) => {
				const digest = hash(`asset sweep ${input.kind} ${call.txid}`);
				const signature = context.sign({
					transactionInputIndex: input.transactionInputIndex,
					publicKey: input.publicKey,
					sigHash: digest
				});
				if (
					!ecc.verifySchnorr(digest, input.publicKey.subarray(1), signature)
				) {
					throw new Error(
						'the host signed with another key than the one of the input'
					);
				}
				return signature;
			});
			const right: IAuxiliarySweepResult = {
				// A second-level HTLC transaction keeps the output the peer
				// signed for; every other sweep sends the units to one script.
				outputScripts: new Map([
					[
						0,
						context.inputs.some((input) =>
							input.kind.startsWith('htlc_second_level')
						)
							? Buffer.from(context.transaction.outs[0].script)
							: Buffer.from(ASSET_SWEEP_SCRIPT)
					]
				]),

				customData: Buffer.concat([Buffer.from(sweepData(call)), ...signatures])
			};
			return control.answer
				? (control.answer(context, right) as IAuxiliarySweepResult)
				: right;
		}
	};
}

export interface IAssetChainPair {
	chain: TestChain;
	alice: IAssetHost;
	bob: IAssetHost;
	backends: { alice: TestChainBackend; bob: TestChainBackend };
	/** Every time either provider was asked for the asset side of a sweep. */
	sweeps: { alice: ISweepCall[]; bob: ISweepCall[] };

	/** The wallet whose coins pay the fees of a host's fixed-output spends. */
	wallets: { alice?: IChainWallet; bob?: IChainWallet };

	/** The database file of Alice, who can be restarted from it. */
	alicePath: string;
	channelId: Buffer;
	funding: bitcoin.Transaction;
}

export interface IAssetChainOptions {
	openerUnits?: bigint;
	acceptorUnits?: bigint;
	fundingSatoshis?: bigint;
	pushMsat?: bigint;
	/**
	 * Each node reads the features the other really advertises, in place
	 * of the fixed set the hosts of these tests are otherwise told.
	 */
	realInit?: boolean;
	control?: { alice?: ISweepControl; bob?: ISweepControl };

	/** Give a host a wallet on the chain and the real fee pool over it. */
	feeWallet?: {
		alice?: Partial<IFixedOutputFeePolicy> | true;
		bob?: Partial<IFixedOutputFeePolicy> | true;
	};

	hooks?: {
		alice?: Partial<IAuxiliaryChannelConfig>;
		bob?: Partial<IAuxiliaryChannelConfig>;
	};
}

/** Alice pays Bob `units` over the asset channel of a pair, and it settles. */
export async function payUnits(
	pair: IAssetChainPair,
	units: bigint
): Promise<void> {
	const { alice, bob, channelId, chain } = pair;
	const invoice = bob.node.createInvoice({
		amountMsat: units * 1000n,
		description: 'units'
	});
	const expiry = chain.height + 60;
	alice.node.sendPaymentToRoute(
		{
			hops: [
				{
					pubkey: Buffer.from(bob.node.getNodeId(), 'hex'),
					shortChannelId: Buffer.alloc(8, 9),
					amountToForwardMsat: units * 1000n,
					outgoingCltvValue: expiry
				}
			]
		},
		invoice.paymentHash,
		expiry,
		invoice.paymentSecret,
		undefined,
		undefined,
		undefined,
		undefined,
		{
			assetPayment: {
				channelId,
				wireAmountMsat: 354_000n,
				customRecords: amountRecord(units)
			}
		}
	);
	await settle();
	const status = alice.node.getPayment(invoice.paymentHash)?.status;
	if (status !== PaymentStatus.COMPLETED) {
		throw new Error(
			`a payment of ${units} units is ${status}: ${alice.errors
				.concat(bob.errors)
				.join('; ')}`
		);
	}
}

/**
 * Alice offers Bob `units` against a hold invoice, and the HTLC stays in
 * flight on both sides: Bob holds the preimage and has not used it. Bob's
 * host needs the `valueIncomingHtlc` hook.
 */
export async function holdUnits(
	pair: IAssetChainPair,
	units: bigint,
	tag: string,
	expiryDelta = 60,
	/** False for an offer that is not to reach the peer, or not to stay. */
	inFlight = true
): Promise<{
	paymentHash: Buffer;
	preimage: Buffer;
	cltvExpiry: number;
	paymentSecret: Buffer;
}> {
	const { alice, bob, channelId, chain } = pair;
	const preimage = hash(`held preimage ${tag}`);
	const paymentHash = crypto.createHash('sha256').update(preimage).digest();
	const invoice = bob.node.createInvoice({
		amountMsat: units * 1000n,
		description: `held ${tag}`,
		hold: true,
		paymentHash
	});

	const asked = chain.height + expiryDelta;
	alice.node.sendPaymentToRoute(
		{
			hops: [
				{
					pubkey: Buffer.from(bob.node.getNodeId(), 'hex'),
					shortChannelId: Buffer.alloc(8, 9),

					amountToForwardMsat: units * 1000n,
					outgoingCltvValue: asked
				}
			]
		},
		invoice.paymentHash,
		expiryDelta,

		invoice.paymentSecret,
		undefined,
		undefined,
		undefined,
		undefined,
		{
			assetPayment: {
				channelId,
				wireAmountMsat: 354_000n,
				customRecords: amountRecord(units)
			}
		}
	);
	await settle();

	const entries = [
		...(bob.node
			.getChannelManager()
			.getChannel(channelId)
			?.getFullState()
			.htlcs.values() ?? [])
	].filter((entry) => entry.paymentHash.equals(paymentHash));
	// The expiry the HTLC has in the channel, which is what the chain goes by.
	const cltvExpiry = entries[0]?.cltvExpiry ?? 0;
	if (inFlight && entries.length !== 1) {
		throw new Error(
			`the held HTLC of ${tag} is not in flight: ${alice.errors
				.concat(bob.errors)
				.join('; ')}`
		);
	}
	return {
		paymentHash,
		preimage,
		cltvExpiry,
		paymentSecret: invoice.paymentSecret
	};
}

/** The two hosts of a pair stop hearing each other, as when a connection drops. */
export function disconnect(pair: IAssetChainPair): void {
	pair.alice.node.removeAllListeners('message:outbound');
	pair.bob.node.removeAllListeners('message:outbound');
	pair.alice.node
		.getChannelManager()
		.handlePeerDisconnected(pair.bob.node.getNodeId());
	pair.bob.node
		.getChannelManager()
		.handlePeerDisconnected(pair.alice.node.getNodeId());
}

/**
 * Alice offers Bob `units` once more for a payment hash Bob has an invoice
 * for already, whatever has become of that invoice since.
 */
export async function offerUnitsAgain(
	pair: IAssetChainPair,
	units: bigint,
	paymentHash: Buffer,
	paymentSecret: Buffer,
	expiryDelta = 60
): Promise<void> {
	const { alice, bob, channelId, chain } = pair;
	alice.node.sendPaymentToRoute(
		{
			hops: [
				{
					pubkey: Buffer.from(bob.node.getNodeId(), 'hex'),
					shortChannelId: Buffer.alloc(8, 9),
					amountToForwardMsat: units * 1000n,
					outgoingCltvValue: chain.height + expiryDelta
				}
			]
		},
		paymentHash,
		expiryDelta,
		paymentSecret,
		undefined,
		undefined,
		undefined,
		undefined,
		{
			assetPayment: {
				channelId,
				wireAmountMsat: 354_000n,
				customRecords: amountRecord(units)
			}
		}
	);
	await settle();
}

/**
 * Test only: stand between one node and the other. What the gate refuses
 * is kept, in order, and `release()` hands it over; everything else that
 * node sends passes as before, and so does all the other node sends.
 */
export function gateMessages(
	pair: IAssetChainPair,
	from: 'alice' | 'bob',
	refuse: (type: number, payload: Buffer) => boolean
): { kept: Array<{ type: number; payload: Buffer }>; release: () => void } {
	const sender = pair[from].node;
	const receiver = pair[from === 'alice' ? 'bob' : 'alice'].node;
	const kept: Array<{ type: number; payload: Buffer }> = [];
	const deliver = (type: number, payload: Buffer): void => {
		receiver.handlePeerMessage(sender.getNodeId(), type, payload);
	};
	sender.removeAllListeners('message:outbound');
	sender.on(
		'message:outbound',
		(pubkey: string, type: number, payload: Buffer) => {
			if (pubkey !== receiver.getNodeId()) return;
			if (refuse(type, payload)) kept.push({ type, payload });
			else deliver(type, payload);
		}
	);
	return {
		kept,
		release: (): void => {
			for (const message of kept.splice(0)) {
				deliver(message.type, message.payload);
			}
		}
	};
}

/** The outputs a host's monitor tracks for a channel, through the host's read. */
export const trackedOutputs = (
	host: IAssetHost,
	channelId: Buffer
): ITrackedOutput[] =>
	host.node.getChannelMonitorState(channelId)?.trackedOutputs ?? [];

/** A spend a host signed for an output of its asset channel, as a block has it. */
export interface IOwnSpend {
	output: ITrackedOutput;
	transaction: bitcoin.Transaction;
	height: number;
	vbytes: number;
	fee: number;
}

/**
 * Every spend of a tracked output that is in a block and is one the host
 * signed itself, with the size it really has and the fee it really pays:
 * all it spends less all it pays out.
 */
export function ownSpends(
	pair: IAssetChainPair,
	host: IAssetHost
): IOwnSpend[] {
	const spends: IOwnSpend[] = [];
	for (const output of trackedOutputs(host, pair.channelId)) {
		if (!output.resolutionTxid) continue;
		const signed = new Set(Object.keys(output.auxiliarySweepAttempts ?? {}));
		if (output.sweepTxHex) {
			signed.add(bitcoin.Transaction.fromHex(output.sweepTxHex).getId());
		}
		const entry = pair.chain.confirmed.get(output.resolutionTxid);
		if (!entry || !signed.has(output.resolutionTxid)) continue;
		let paidIn = 0;
		for (const input of entry.tx.ins) {
			const previous = pair.chain.confirmed.get(
				Buffer.from(input.hash).reverse().toString('hex')
			);
			if (!previous) throw new Error('a spend of an unknown output');
			paidIn += previous.tx.outs[input.index].value;
		}
		spends.push({
			output,
			transaction: entry.tx,
			height: entry.height,
			vbytes: entry.tx.virtualSize(),
			fee: paidIn - entry.tx.outs.reduce((sum, out) => sum + out.value, 0)
		});
	}
	return spends;
}

/**
 * The spends of either host of a pair that pay less than the rate their
 * output was first given a spend at, for the size they really have, and
 * every transaction the chain refused as below the relay floor.
 */
export function underpaidSpends(pair: IAssetChainPair): string[] {
	const found: string[] = [];
	for (const [name, host] of [
		['alice', pair.alice],
		['bob', pair.bob]
	] as const) {
		for (const spend of ownSpends(pair, host)) {
			const rate = spend.output.originalFeeRate ?? 1;
			if (spend.fee < Math.ceil(spend.vbytes * rate)) {
				found.push(
					`${name}: the spend of ${spend.output.outputType} ${spend.output.txid}:${spend.output.outputIndex} pays ${spend.fee} sat for ${spend.vbytes} vB with ${spend.transaction.ins.length} inputs, asked at ${rate} sat/vB`
				);
			}
		}
		for (const refusal of pair.backends[name].refused) {
			if (refusal.reason.includes('minimum relay fee')) {
				found.push(`${name}: ${refusal.reason}`);
			}
		}
	}
	return found;
}

/** What a host said went wrong, without what a node with no wallet always says. */
export const errorsOf = (host: IAssetHost): string[] =>
	host.errors.filter(
		(error) =>
			!error.startsWith('AUTO_FUNDING_FAILED') &&
			!error.startsWith('NO_ROUTING_HINTS') &&
			!error.includes('anchor fee bump')
	);

/**
 * The hosts, backends and files of one test, and how to make them. `dispose`
 * goes in an afterEach.
 */
export function assetChainWorld(): {
	open(tag: string, options?: IAssetChainOptions): Promise<IAssetChainPair>;
	/** Stop Alice and start her again from her database, on the same chain. */
	restartAlice(
		pair: IAssetChainPair,
		tag: string,
		control?: ISweepControl,
		/** Runs while Alice is down, as what puts another copy of her store in place. */
		whileDown?: () => void,
		/** The hooks her host has again once she is back. */
		hooks?: Partial<IAuxiliaryChannelConfig>
	): Promise<void>;
	mine(pair: IAssetChainPair, blocks: number): Promise<void>;
	/**
	 * What `underpaidSpends` finds on every pair opened since the last
	 * `dispose`: asked before it, at the end of a test that passed.
	 */
	underpaid(): string[];
	dispose(): void;
} {
	const hosts: IAssetHost[] = [];
	const pairs: IAssetChainPair[] = [];
	const backends: TestChainBackend[] = [];
	const files: string[] = [];

	const onChain = async (
		tag: string,
		seed: number,
		chain: TestChain,
		calls: ISweepCall[],
		control: ISweepControl | undefined,
		hooks: Partial<IAuxiliaryChannelConfig> | undefined,

		sqlitePath: string | undefined,
		wallet?: IChainWallet
	): Promise<{ host: IAssetHost; backend: TestChainBackend }> => {
		const backend = new TestChainBackend(chain);
		backends.push(backend);
		wallet?.attach(backend);

		// The secrets of the basepoints a loopback node is made with: what it
		// signs a sweep or a penalty with.
		const secret = (index: number): Buffer =>
			crypto
				.createHash('sha256')
				.update(makeSeed(tag, seed))
				.update(Buffer.from([index]))
				.digest();
		const host = assetHost(
			tag,
			seed,
			{ provider: sweepingProvider(calls, control), ...hooks },
			{
				...(sqlitePath ? { sqlitePath } : { sqlite: true }),
				extra: {
					chainBackend: backend,
					...(wallet ? { fundingProvider: wallet.provider() } : {}),
					revocationBasepointSecret: secret(1),

					paymentBasepointSecret: secret(2),
					delayedPaymentBasepointSecret: secret(3)
				}
			}
		);
		hosts.push(host);
		await host.node.startChainWatcher();
		return { host, backend };
	};

	const mine = async (pair: IAssetChainPair, blocks: number): Promise<void> => {
		for (let i = 0; i < blocks; i++) {
			pair.chain.mine();
			await settle();
		}
	};

	return {
		mine,
		underpaid: (): string[] => pairs.flatMap((pair) => underpaidSpends(pair)),
		async open(tag, options = {}): Promise<IAssetChainPair> {
			const chain = new TestChain();
			const alicePath = path.join(
				os.tmpdir(),
				`${tag}-${process.pid}-${crypto.randomBytes(4).toString('hex')}.sqlite`
			);
			files.push(alicePath, `${alicePath}-wal`, `${alicePath}-shm`);
			const sweeps = { alice: [] as ISweepCall[], bob: [] as ISweepCall[] };

			const walletOf = (who: 'alice' | 'bob'): IChainWallet | undefined => {
				const asked = options.feeWallet?.[who];
				return asked
					? chainWallet(chain, `${tag} ${who}`, asked === true ? {} : asked)
					: undefined;
			};
			const wallets = { alice: walletOf('alice'), bob: walletOf('bob') };

			const { host: alice, backend: aliceBackend } = await onChain(
				tag,
				1,
				chain,
				sweeps.alice,
				options.control?.alice,
				options.hooks?.alice,
				alicePath,
				wallets.alice
			);
			const { host: bob, backend: bobBackend } = await onChain(
				tag,
				2,
				chain,
				sweeps.bob,
				options.control?.bob,
				options.hooks?.bob,
				undefined,
				wallets.bob
			);
			if (options.realInit) {
				const reads = (host: IAssetHost, peer: IAssetHost): void => {
					(
						host.node as unknown as { peerInitFeatures: () => unknown }
					).peerInitFeatures = (): unknown => peer.node.getLocalFeatures();
				};
				reads(alice, bob);
				reads(bob, alice);
			}
			connectHosts(alice, bob);
			const openerUnits = options.openerUnits ?? 9000n;
			const acceptorUnits = options.acceptorUnits ?? 1000n;
			const fundingSatoshis = options.fundingSatoshis ?? 2_000_000n;
			const descriptor: IAuxiliaryFundingDescriptor = {
				temporaryChannelId: hash(`asset channel ${tag}`),
				fundingTaprootMerkleRoot: Buffer.from(ASSET_FUNDING_ROOT),
				channelData: Buffer.from('proposed asset funding'),
				localBalance: openerUnits,
				remoteBalance: acceptorUnits
			};
			bob.incoming.set(descriptor.temporaryChannelId.toString('hex'), {
				...descriptor,
				localBalance: acceptorUnits,
				remoteBalance: openerUnits
			});
			const channel = alice.node.openAuxiliaryChannel(
				bob.node.getNodeId(),
				fundingSatoshis,
				descriptor,
				options.pushMsat ?? 500_000_000n
			);
			await settle();
			const state = channel.getFullState();
			const funding = new bitcoin.Transaction();
			funding.version = 2;
			funding.addInput(hash(`asset funding input ${tag}`), 0);
			funding.addOutput(Buffer.from('6a', 'hex'), 0);
			funding.addOutput(
				createTaprootFundingScript(
					state.localBasepoints.fundingPubkey,
					state.remoteBasepoints!.fundingPubkey,
					undefined,
					ASSET_FUNDING_ROOT
				).p2trOutput,
				Number(fundingSatoshis)
			);
			const channelId = alice.node.fundAuxiliaryChannel(
				bob.node.getNodeId(),
				descriptor.temporaryChannelId,
				funding.toHex(),
				1,
				Buffer.from('final funding proofs'),
				{ prevoutScripts: [SWEEP_DESTINATION] }
			);
			await settle();
			// Somebody else signs and publishes the funding, and blocks pass.
			const signed = funding.clone();
			signed.setWitness(0, [Buffer.alloc(72, 7), Buffer.alloc(33, 2)]);
			chain.seed(signed);
			await settle();
			const pair: IAssetChainPair = {
				chain,
				alice,
				bob,
				backends: { alice: aliceBackend, bob: bobBackend },
				sweeps,
				wallets,
				alicePath,
				channelId,
				funding
			};
			pairs.push(pair);
			await mine(pair, 6);
			for (const host of [alice, bob]) {
				const now = host.node
					.getChannelManager()
					.getChannel(channelId)
					?.getState();
				if (now !== ChannelState.NORMAL) {
					throw new Error(
						`the asset channel of ${tag} is ${now}: ${host.errors.join('; ')}`
					);
				}
			}
			return pair;
		},
		async restartAlice(pair, tag, control, whileDown, hooks): Promise<void> {
			pair.alice.node.destroy();
			pair.alice.storage?.close();
			pair.backends.alice.close();
			pair.bob.node.removeAllListeners('message:outbound');
			pair.bob.node
				.getChannelManager()
				.handlePeerDisconnected(pair.alice.node.getNodeId());
			pair.sweeps.alice = [];

			whileDown?.();
			const { host, backend } = await onChain(
				tag,
				1,
				pair.chain,
				pair.sweeps.alice,
				control,
				hooks,
				pair.alicePath,
				pair.wallets.alice
			);
			pair.alice = host;
			pair.backends.alice = backend;
			await settle();
		},
		dispose(): void {
			pairs.splice(0);
			for (const host of hosts.splice(0)) {
				try {
					host.node.destroy();
				} catch {
					// Destroyed by a restart already.
				}
				try {
					host.storage?.close();
				} catch {
					// Closed by a restart already.
				}
			}
			for (const backend of backends.splice(0)) backend.close();
			for (const file of files.splice(0)) fs.rmSync(file, { force: true });
		}
	};
}

/**
 * The monitor's row reads back as it was written: what the reader makes of
 * the row writes the same row again, and each named field, which some
 * tracked output must carry, comes back with the value it had.
 */
export function monitorRoundTrips(
	host: IAssetHost,
	channelId: Buffer,
	fields: string[]
): void {
	const state = host.node.getChannelMonitorState(channelId)!;
	const row = serializeChainMonitorState(state);
	const back = deserializeChainMonitorState(row);
	assert.strictEqual(serializeChainMonitorState(back), row);
	const read = (output: unknown, field: string): unknown =>
		(output as Record<string, unknown>)[field];
	for (const field of fields) {
		assert.ok(
			state.trackedOutputs.some((output) => read(output, field) !== undefined),
			`no tracked output carries ${field}`
		);
		state.trackedOutputs.forEach((output, at) => {
			assert.deepStrictEqual(
				read(back.trackedOutputs[at], field),
				read(output, field),
				field
			);
		});
	}
}
