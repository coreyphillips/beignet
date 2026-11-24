import { Transaction } from 'bitcoinjs-lib';
import type { SqliteStorage } from '../../../src/lightning/storage/sqlite-storage';
import { createTaprootFundingScript } from '../../../src/lightning/script/funding-taproot';
import { FeatureFlags } from '../../../src/lightning/features/flags';
import { basepointsOf, privAt, seedFor } from './taproot-revoked-fixture';

export type Candidate = Parameters<SqliteStorage['rememberFinalOpening']>[0];
export const wallet = {
	encryptionKey: seedFor(169),
	nodeId: basepointsOf(seedFor(170)).fundingPubkey.toString('hex'),
	network: 'regtest' as const
};
export const localFundingSecret = privAt(seedFor(171), 0);
export const remoteFundingSecret = privAt(seedFor(172), 0);
const localKey = basepointsOf(seedFor(171)).fundingPubkey;
const remoteKey = basepointsOf(seedFor(172)).fundingPubkey;

export function channelType(...bits: number[]): string {
	const flags = FeatureFlags.empty();
	for (const bit of bits) flags.setBit(bit);
	return flags.toBuffer().toString('hex');
}

export function inputTransaction(id: number, value: number): Transaction {
	const tx = new Transaction();
	tx.addInput(seedFor(id), 0);
	tx.addOutput(
		Buffer.concat([Buffer.from([0, 20]), seedFor(id + 100).subarray(0, 20)]),
		value
	);
	return tx;
}

export function opening(zeroAcceptor = false): Candidate {
	const fundingTx = new Transaction();
	fundingTx.version = 2;
	const prevTxs = zeroAcceptor
		? [inputTransaction(174, 140_200)]
		: [inputTransaction(175, 90_120), inputTransaction(176, 50_080)];
	for (const prevTx of prevTxs)
		fundingTx.addInput(prevTx.getHash(), 0, 0xfffffffd);
	const output = createTaprootFundingScript(localKey, remoteKey).p2trOutput;
	fundingTx.addOutput(output, 140_000);
	return {
		channelId: seedFor(zeroAcceptor ? 177 : 178).toString('hex'),
		channelType: zeroAcceptor ? channelType(80, 46) : channelType(80),
		localFundingPubkey: localKey.toString('hex'),
		remoteFundingPubkey: remoteKey.toString('hex'),
		fundingTxHex: fundingTx.toHex(),
		fundingOutputIndex: 0,
		outputSerialIds: ['2'],
		isInitiator: !zeroAcceptor,
		fundingFeeratePerKw: 253,
		minimumDepth: 3,
		localContributionSats: zeroAcceptor ? 0 : 90_000,
		remoteContributionSats: zeroAcceptor ? 140_000 : 50_000,
		inputs: prevTxs.map((tx, index) => ({
			prevTxHex: tx.toHex(),
			isLocal: !zeroAcceptor && index === 0,
			serialId: index === 0 ? '0' : '18446744073709551615'
		}))
	};
}
