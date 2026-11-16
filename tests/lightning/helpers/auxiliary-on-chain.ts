/**
 * Asset channels on a chain (issue #2093): two hosts, each with its own
 * connection to a test chain and its own chain watcher, an asset channel
 * between them whose funding is in a block, and a provider that makes the
 * asset side of a sweep and remembers what it was asked.
 */

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
				outputScripts: new Map([[0, Buffer.from(ASSET_SWEEP_SCRIPT)]]),
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
	control?: { alice?: ISweepControl; bob?: ISweepControl };
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

/** The outputs a host's monitor tracks for a channel, through the host's read. */
export const trackedOutputs = (
	host: IAssetHost,
	channelId: Buffer
): ITrackedOutput[] =>
	host.node.getChannelMonitorState(channelId)?.trackedOutputs ?? [];

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
		control?: ISweepControl
	): Promise<void>;
	mine(pair: IAssetChainPair, blocks: number): Promise<void>;
	dispose(): void;
} {
	const hosts: IAssetHost[] = [];
	const backends: TestChainBackend[] = [];
	const files: string[] = [];

	const onChain = async (
		tag: string,
		seed: number,
		chain: TestChain,
		calls: ISweepCall[],
		control: ISweepControl | undefined,
		hooks: Partial<IAuxiliaryChannelConfig> | undefined,
		sqlitePath: string | undefined
	): Promise<{ host: IAssetHost; backend: TestChainBackend }> => {
		const backend = new TestChainBackend(chain);
		backends.push(backend);
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
		async open(tag, options = {}): Promise<IAssetChainPair> {
			const chain = new TestChain();
			const alicePath = path.join(
				os.tmpdir(),
				`${tag}-${process.pid}-${crypto.randomBytes(4).toString('hex')}.sqlite`
			);
			files.push(alicePath, `${alicePath}-wal`, `${alicePath}-shm`);
			const sweeps = { alice: [] as ISweepCall[], bob: [] as ISweepCall[] };
			const { host: alice, backend: aliceBackend } = await onChain(
				tag,
				1,
				chain,
				sweeps.alice,
				options.control?.alice,
				options.hooks?.alice,
				alicePath
			);
			const { host: bob, backend: bobBackend } = await onChain(
				tag,
				2,
				chain,
				sweeps.bob,
				options.control?.bob,
				options.hooks?.bob,
				undefined
			);
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
				alicePath,
				channelId,
				funding
			};
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
		async restartAlice(pair, tag, control): Promise<void> {
			pair.alice.node.destroy();
			pair.alice.storage?.close();
			pair.backends.alice.close();
			pair.bob.node.removeAllListeners('message:outbound');
			pair.bob.node
				.getChannelManager()
				.handlePeerDisconnected(pair.alice.node.getNodeId());
			pair.sweeps.alice = [];
			const { host, backend } = await onChain(
				tag,
				1,
				pair.chain,
				pair.sweeps.alice,
				control,
				undefined,
				pair.alicePath
			);
			pair.alice = host;
			pair.backends.alice = backend;
			await settle();
		},
		dispose(): void {
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
