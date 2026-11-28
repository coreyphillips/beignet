import { mnemonicToSeedSync } from 'bip39';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { nodeStorageView } from '../../../src/cli/node-storage-view';
import type { IAuxiliaryDualFunding } from '../../../src/lightning/channel/asset-opening-provider';
import type { FeatureFlags } from '../../../src/lightning/features/flags';
import { Network } from '../../../src/lightning/invoice/types';
import { bip32RootFromSeed } from '../../../src/lightning/keys/wallet-keys';
import { LightningNode } from '../../../src/lightning/node/lightning-node';
import type { IFundingProvider } from '../../../src/lightning/node/types';
import { bindFinalDaemonView } from '../../../src/lightning/storage/final-daemon-admission';
import { SqliteStorage } from '../../../src/lightning/storage/sqlite-storage';
import { TestChain, TestChainBackend } from './auxiliary-chain';
import { referenceProvider } from './auxiliary-pair';
import {
	generateFinalGeneration,
	type FinalGeneration
} from './final-generation';

/**
 * The six conversion members of step 3b: step 3a's three terms calls and
 * step 3b's three planner calls.
 */
export const CONVERSION_3B_MEMBERS = [
	'conversionTerms',
	'verifyConversionTerms',
	'abandonConversion',
	'proposeConversion',
	'describeConversion',
	'prepareConversion'
] as const;

/** The three signing members of #2151 Step 4b (contract section 9.3). */
export const CONVERSION_SIGNING_MEMBERS = [
	'signConversionExits',
	'verifyConversionExits',
	'retainConversionExits'
] as const;

/**
 * The nine conversion members of a host, which completeAssetConversionHost
 * requires beside its version and margin since Step 4b (contract 9.5).
 */
export const CONVERSION_HOST_MEMBERS = [
	...CONVERSION_3B_MEMBERS,
	...CONVERSION_SIGNING_MEMBERS
] as const;

/** Every key of the conversion surface: the six members, the version and the margin. */
export const CONVERSION_HOST_KEYS = [
	...CONVERSION_HOST_MEMBERS,
	'assetConversionVersion',
	'conversionFeerateMarginPerKw'
] as const;

const callbacks = [
	'contribution',
	'abandon',
	'propose',
	'describe',
	'prepare',
	'signExits',
	'verifyExits',
	'signFunding',
	'confirmFunding',
	'retractFunding',
	'recoverOutput',
	'recoverHtlc',
	'outputRecoveryReceipt',
	'restoreOutputReceipt',
	'proposeSplice',
	'spliceContribution',
	'abandonSplice',
	'describeSplice',
	'prepareSplice',
	'signSpliceExits',
	'verifySpliceExits',
	'retainSpliceExits',
	'signSpliceFunding',
	'verifySpliceFunding',
	'confirmSpliceFunding',
	'retractSpliceFunding',
	'signAssetUpdateViews',
	'signAssetUpdateHtlcs',
	'verifyAssetUpdateViews',
	'retainAssetUpdateViews',
	'retainAssetUpdatePeerViews',
	...CONVERSION_HOST_MEMBERS
];

/**
 * A stub host that passes completeAssetOpeningHost, completeAssetSpliceHost,
 * completeAssetSpliceRecoveryHost and completeAssetConversionHost, and is
 * never asked to act. Every callback records its name and throws, so a test
 * sees any call. `without` leaves out one key, or several: any callback,
 * `assetConversionVersion` or `conversionFeerateMarginPerKw`.
 */
export function completeRecoveryHost(
	calls: string[] = [],
	without?: string | readonly string[]
): IAuxiliaryDualFunding {
	const left = new Set<string>(
		without === undefined
			? []
			: typeof without === 'string'
			? [without]
			: without
	);
	return {
		version: 1,
		assetSpliceRecoveryVersion: 1,
		...(!left.has('assetConversionVersion') && { assetConversionVersion: 1 }),
		...(!left.has('conversionFeerateMarginPerKw') && {
			conversionFeerateMarginPerKw: 0
		}),
		...Object.fromEntries(
			callbacks
				.filter((name) => !left.has(name))
				.map((name) => [
					name,
					() => {
						calls.push(name);
						throw new Error('Stub asset host was asked to ' + name);
					}
				])
		)
	} as unknown as IAuxiliaryDualFunding;
}

export interface IFinalTestNode {
	node: LightningNode;
	db: SqliteStorage;
	calls: string[];
	errors: string[];
	close(): void;
}

/**
 * A LightningNode over a final wallet, adapted from the factory of
 * dual-funded-assets-open.test.ts. Pass `wallet` to run a node over an
 * existing store (its seed and mnemonic), otherwise a fresh wallet of
 * `generation` is enrolled.
 */
export function finalTestNode(
	generation: FinalGeneration,
	options: {
		host?: IAuxiliaryDualFunding | null;
		wallet?: { db: SqliteStorage; mnemonic: string };
		localFeatures?: FeatureFlags;
	} = {}
): IFinalTestNode {
	const dir = mkdtempSync(join(tmpdir(), 'asset-conversion-node-'));
	let db: SqliteStorage, mnemonic: string;
	if (options.wallet) ({ db, mnemonic } = options.wallet);
	else {
		const fresh = generateFinalGeneration(generation);
		mnemonic = fresh.mnemonic;
		db = SqliteStorage.createFinalWallet(
			join(dir, 'lightning.db'),
			fresh.binding
		);
	}
	const seed = mnemonicToSeedSync(mnemonic);
	const storage = nodeStorageView(db) as SqliteStorage;
	const chain = new TestChain();
	const chainBackend = new TestChainBackend(chain);
	const calls: string[] = [];
	const unexpected = async (): Promise<never> => {
		calls.push('unexpected funding call');
		throw Error('Funding is not part of this test');
	};
	const fundingProvider: IFundingProvider = {
		buildFundingTransaction: unexpected,
		broadcastTransaction: async (hex) => chainBackend.broadcastTransaction(hex),
		resolveFinalOpeningInputs: unexpected,
		supportsFixedOutputFees: () => true
	};
	bindFinalDaemonView(
		storage,
		bip32RootFromSeed(seed),
		fundingProvider,
		chainBackend
	);
	const host =
		options.host === undefined ? completeRecoveryHost(calls) : options.host;
	const node = LightningNode.fromMnemonic(mnemonic, {
		network: Network.REGTEST,
		seed,
		storage,
		chainBackend,
		fundingProvider,
		peerStorageEnabled: false,
		...(options.localFeatures && { localFeatures: options.localFeatures }),
		auxiliaryChannels: {
			provider: referenceProvider(),
			resolveIncoming: () => undefined,
			...(host && { dualFunding: host })
		}
	});
	const errors: string[] = [];
	node.getChannelManager().on('error', (_id, message) => errors.push(message));
	return {
		node,
		db,
		calls,
		errors,
		close() {
			node.destroy();
			chainBackend.close();
			if (!options.wallet) db.close();
			rmSync(dir, { recursive: true, force: true });
		}
	};
}

/** The transport supplies these init vectors before delivering channel messages. */
export function announce(node: LightningNode, remote: FeatureFlags): void {
	(node as unknown as { peerInitFeatures(): FeatureFlags }).peerInitFeatures =
		() => remote;
}
