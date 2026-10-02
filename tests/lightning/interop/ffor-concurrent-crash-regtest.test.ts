import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import { LightningNode } from '../../../src/lightning/node/lightning-node';
import { INodeConfig, PaymentStatus } from '../../../src/lightning/node/types';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../../src/lightning/channel/types';
import { ChannelActionType } from '../../../src/lightning/channel/channel-actions';
import {
	FforState,
	FF_RECONCILE_MARGIN_BLOCKS
} from '../../../src/lightning/ffor/types';
import { createFundingScript } from '../../../src/lightning/script/funding';
import { decodeFforSyncReplyMessage } from '../../../src/lightning/ffor/messages';
import { ChannelRecoveryStatus } from '../../../src/lightning/recovery/channel-status';
import {
	createChaosNode,
	makeChaosNodeConfig,
	buildDirectGraph,
	chaosWait,
	IChaosEnv,
	IChaosScenario,
	runKillMatrix,
	openChaosStorage,
	IChaosEnvOptions
} from '../helpers/chaos-harness';
import { REGTEST } from '../helpers/ffor-world';
import { bitcoinRpc, ensureBitcoindFunds, mineBlocks } from './shared-helpers';
import { bitcoindUp, tipHeight } from './ffor-concurrent-helpers';

const S_SEED = 91;
const R_SEED = 92;
const AMOUNT = 1000000n;
const extra: Partial<INodeConfig> = {
	fforConcurrent: { enabled: true },
	fforSettle: { enabled: true, allowConcurrent: true },
	channelConfig: { ...DEFAULT_CHANNEL_CONFIG, feeratePerKw: 2500 }
};

function features(s: LightningNode, r: LightningNode): void {
	s.getChannelManager().setFforPeerFeatureSource((peer) =>
		peer === r.getNodeId() ? r.getLocalFeatures() : null
	);
	r.getChannelManager().setFforPeerFeatureSource((peer) =>
		peer === s.getNodeId() ? s.getLocalFeatures() : null
	);
}

describe('Concurrent receive durable boundary qualification on regtest', function () {
	this.timeout(600000);
	let fundingTx: bitcoin.Transaction;
	let fundingIndex: number;
	let height: number;
	before(async () => {
		if (!(await bitcoindUp()))
			throw new Error('Bitcoin Core regtest is required');
		await ensureBitcoindFunds(2);
		const script = createFundingScript(
			makeChaosNodeConfig(S_SEED).channelBasepoints!.fundingPubkey,
			makeChaosNodeConfig(R_SEED).channelBasepoints!.fundingPubkey,
			REGTEST
		);
		const txid = (await bitcoinRpc('sendtoaddress', [
			script.address,
			0.01
		])) as string;
		await mineBlocks(1);
		fundingTx = bitcoin.Transaction.fromHex(
			(await bitcoinRpc('getrawtransaction', [txid])) as string
		);
		fundingIndex = fundingTx.outs.findIndex((output) =>
			Buffer.from(output.script).equals(script.p2wshOutput)
		);
		expect(fundingIndex).to.be.greaterThan(-1);
		height = await tipHeight();
	});

	for (const version of [1, 2] as const)
		for (const role of ['S', 'R'] as const)
			for (const operation of ['send', 'receive', 'proof', 'sync'] as const) {
				it(`version ${version}, ${role} restart during ${operation}: every durable boundary resumes with current commitments`, async () => {
					const sides = (
						env: IChaosEnv,
						victim = env.victim
					): { s: LightningNode; r: LightningNode } =>
						role === 'S'
							? { s: victim, r: env.peers[0] }
							: { s: env.peers[0], r: victim };
					const options: IChaosEnvOptions = {
						victimSeedId: role === 'S' ? S_SEED : R_SEED,
						peerSeedIds: [role === 'S' ? R_SEED : S_SEED],
						victimExtras: extra,
						peerFactory: (seed) => createChaosNode(seed, { extras: extra }),
						afterRestart: (env, restored) => {
							const { s, r } = sides(env, restored);
							features(s, r);
							restored.handleNewBlock(height);
							if (operation === 'proof' && role === 'R') {
								const disk = openChaosStorage(env.dbPath);
								const hash = (env.scratch.hashes as string[])[0];
								const proof =
									disk.loadPreimage(hash) ??
									disk.loadChannel(env.channelId!.toString('hex'))!.state.ffor!
										.knownPreimages[0];
								disk.close();
								env.scratch.restoredProof = proof?.toString('hex');
								if (
									env.kill.firedLabel !==
									`pre-commit:${env.scratch.firstProofCommit}`
								)
									expect(
										proof?.equals(env.scratch.preimage as Buffer),
										`committed proof survives before reconnect or resubmission at ${env.kill.firedLabel}`
									).to.equal(true);
							}
						}
					};
					const scenario = (): IChaosScenario => ({
						name: `concurrent ${version} ${role} ${operation}`,
						async setup(env): Promise<void> {
							const { s, r } = sides(env);
							features(s, r);
							s.handleNewBlock(height);
							r.handleNewBlock(height);
							const pending = s.openChannel(
								r.getNodeId(),
								1000000n,
								200000000n
							);
							env.channelId = s.createFunding(
								pending,
								fundingTx.getHash(),
								fundingIndex,
								crypto.randomBytes(64)
							)!;
							s.handleFundingConfirmed(env.channelId);
							r.handleFundingConfirmed(env.channelId);
							buildDirectGraph(s, S_SEED, R_SEED);
							buildDirectGraph(r, R_SEED, S_SEED);
							const result = r.startFforEpoch(env.channelId.toString('hex'), {
								voucherAmountsMsat: [AMOUNT, AMOUNT],
								minPaymentMsat: AMOUNT,
								settlementDeadline: height + 200,
								voucherExpiry: height + 200 + FF_RECONCILE_MARGIN_BLOCKS,
								feeBaseMsat: 1000,
								feeProportionalMillionths: 5000,
								concurrent: true,
								concurrentVersion: version
							});
							expect(result.ok, result.error).to.be.true;
							const epoch = s
								.getChannelManager()
								.getChannel(env.channelId)!
								.getFforEpoch()!;
							env.scratch.preimage = Buffer.from(epoch.preimages[0]);
							env.scratch.hashes = epoch.paymentHashes.map((hash) =>
								hash.toString('hex')
							);
							r.createFforVoucherInvoice(env.channelId.toString('hex'), 1);
							if (operation === 'sync')
								expect(
									r.fforAddPreimage(
										env.channelId.toString('hex'),
										epoch.preimages[0]
									).ok
								).to.be.true;
							env.scratch.firstProofCommit = env.commitTap.commitCount + 1;
							if (operation === 'sync')
								expect(
									r.getFforEpoch(env.channelId.toString('hex'))!
										.syncSnapshotWire
								).to.equal(undefined);
						},
						async run(env): Promise<void> {
							const { s, r } = sides(env);
							if (operation === 'send' || operation === 'receive') {
								const sender = operation === 'send' ? env.victim : env.peers[0];
								const receiver = sender === s ? r : s;
								const invoice = receiver.createInvoice({
									amountMsat: 1000000n,
									description: 'ordinary payment with live vouchers'
								});
								const payment = sender.sendPayment(invoice.bolt11);
								await chaosWait(
									env,
									() => payment.status !== PaymentStatus.PENDING
								);
								if (!env.kill.killed)
									expect(payment.status).to.equal(PaymentStatus.COMPLETED);
							} else if (operation === 'proof')
								r.fforAddPreimage(
									env.channelId!.toString('hex'),
									env.scratch.preimage as Buffer
								);
							else r.fforSync(env.channelId!.toString('hex'));
						},
						async probe(env, restored): Promise<void> {
							const { s, r } = sides(env, restored);
							buildDirectGraph(s, S_SEED, R_SEED);
							buildDirectGraph(r, R_SEED, S_SEED);
							const id = env.channelId!.toString('hex');
							if (
								operation === 'proof' &&
								!r.getFforEpoch(id)!.knownPreimages[0]
							)
								expect(
									r.fforAddPreimage(
										id,
										typeof env.scratch.restoredProof === 'string'
											? Buffer.from(env.scratch.restoredProof, 'hex')
											: (env.scratch.preimage as Buffer)
									).ok
								).to.be.true;
							if (operation === 'sync') {
								expect(r.fforSync(id).ok).to.be.true;
								await chaosWait(
									env,
									() => !r.getFforEpoch(id)!.syncRequestWire
								);
								const snapshot = r.getFforEpoch(id)!.syncSnapshotWire;
								expect(snapshot).to.not.equal(undefined);
								const decoded = decodeFforSyncReplyMessage(
									snapshot!.subarray(2)
								);
								expect(decoded.snapshotSeq > 0n).to.equal(true);
								expect(
									decoded.preimages.map((entry) =>
										entry.preimage.toString('hex')
									)
								).to.deep.equal([
									(env.scratch.preimage as Buffer).toString('hex')
								]);
							}
							const sender =
								operation === 'send'
									? restored
									: operation === 'receive'
									? env.peers[0]
									: s;
							const receiver = sender === s ? r : s;
							const invoice = receiver.createInvoice({
								amountMsat: 1000000n,
								description: 'post-restart ordinary payment'
							});
							const payment = sender.sendPayment(invoice.bolt11);
							await chaosWait(
								env,
								() => payment.status !== PaymentStatus.PENDING
							);
							expect(payment.status).to.equal(PaymentStatus.COMPLETED);
						}
					});
					const { schedule, executed } = await runKillMatrix(
						'local',
						scenario,
						() => 'exact-resume',
						async (result) => {
							const { s, r } = sides(result.env, result.restored);
							const id = result.env.channelId!;
							const redeemed = operation === 'proof' || operation === 'sync';
							const hashes = result.env.scratch.hashes as string[];
							if (operation === 'proof' && role === 'R') {
								const disk = JSON.parse(result.postKillDump) as {
									preimages: [string, string][];
									channels: [string, string][];
								};
								const persisted = JSON.parse(
									disk.channels.find(
										([channelId]) => channelId === id.toString('hex')
									)![1]
								);
								if (
									result.firedLabel !==
									`pre-commit:${result.env.scratch.firstProofCommit}`
								) {
									const kept =
										persisted.ffor.knownPreimages[0] ??
										disk.preimages.find(([hash]) => hash === hashes[0])?.[1];
									expect(kept).to.equal(
										(result.env.scratch.preimage as Buffer).toString('hex')
									);
									expect(result.env.scratch.restoredProof).to.equal(kept);
								}
							}
							if (operation === 'sync') {
								const persisted = result.restoredStorage.loadChannel(
									id.toString('hex')
								)!.state.ffor!;
								expect(persisted.syncSnapshotWire?.toString('hex')).to.equal(
									result.restored
										.getFforEpoch(id.toString('hex'))!
										.syncSnapshotWire!.toString('hex')
								);
								if (role === 'R')
									expect(persisted.syncRequestWire).to.equal(undefined);
							}
							for (const node of [s, r]) {
								const channel = node.getChannelManager().getChannel(id)!;
								expect(channel.getState()).to.equal(ChannelState.NORMAL);
								expect(channel.getFforEpoch()!.state).to.equal(
									FforState.ACTIVE
								);
								expect(
									[...channel.getFullState().htlcs.values()].map((htlc) =>
										htlc.paymentHash.toString('hex')
									)
								).to.deep.equal(redeemed ? hashes.slice(1) : hashes);
							}
							for (const status of result.restored.getRecoveryStatus().channels)
								expect(status.status).to.equal(ChannelRecoveryStatus.Active);
							expect(result.broadcasts).to.deep.equal([]);
							if (redeemed)
								expect(
									r.getPayment(Buffer.from(hashes[0], 'hex'))!.status
								).to.equal(PaymentStatus.COMPLETED);
							// No commitment is published. Bitcoin Core validates both current exits
							// against the real, unspent funding output after every restart cell.
							result.env.relay.hold();
							for (const node of [s, r]) {
								const plan = node
									.getChannelManager()
									.forceClose(
										id,
										Buffer.concat([Buffer.from([0, 20]), Buffer.alloc(20, 4)]),
										10,
										REGTEST
									);
								expect(plan.ok, plan.error).to.be.true;
								const action = plan.actions.find(
									(entry) => entry.type === ChannelActionType.BROADCAST_TX
								) as { tx: Buffer };
								const tx = bitcoin.Transaction.fromBuffer(action.tx);
								const [acceptance] = (await bitcoinRpc('testmempoolaccept', [
									[tx.toHex()]
								])) as { allowed: boolean; 'reject-reason'?: string }[];
								expect(acceptance.allowed, acceptance['reject-reason']).to.be
									.true;
							}
						},
						options
					);
					expect(executed).to.equal(schedule.length);
					console.log(
						JSON.stringify({
							version,
							role,
							operation,
							durableBoundaries: executed,
							fundingTxid: fundingTx.getId()
						})
					);
				});
			}
});
