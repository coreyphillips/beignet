/**
 * Recovery Phase 7, component 7: wallet UTXO selection across a kill
 * (docs/RECOVERY-TRANSITION-MATRIX.md section 3, row 8).
 *
 * The row's hazard is the cross-storage-domain window: the funding
 * pledge (a tagged freeze) lives in WALLET storage while the funding
 * commitment lives in LIGHTNING storage, and a kill between the two
 * could leave a restart that either forgets a coin is spoken for
 * (double-selection, two fundings spending one coin) or forgets a
 * funding whose coin stays frozen forever.
 *
 * The sweep kills a wallet-funded channel open at every commit and send
 * boundary and asserts the durable ordering that makes double-selection
 * impossible: the pledge freeze lands INSIDE buildFundingTransaction,
 * before the signed tx is ever handed to the node, so by the time
 * anything lightning-side is durable the wallet already refuses the
 * coin. Concretely, after every kill and restart (fresh provider over
 * the same wallet, the way a real restart reopens the same wallet):
 * - a second funding never selects an input of the first funding's tx
 *   whenever that tx exists anywhere durable (wallet freeze or retained
 *   broadcast obligation);
 * - if the first funding's tx was retained (the BOLT 2 broadcast
 *   obligation), the restart still holds it;
 * - the reverse window (frozen coin, no funding anywhere) is the benign
 *   one the pledge TTL exists for, and is funding-input-pledges.test.ts
 *   territory rather than a kill matter.
 *
 * The transition matrix's original note called this row "not yet
 * implemented"; the pledge mechanism (freeze, restart adoption, TTL
 * pruning under a selection lock) has since landed, and this sweep is
 * the kill-test proof the row demanded. The note is corrected in the
 * matrix alongside this file.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import { WalletFundingProvider } from '../../src/lightning/wallet/wallet-funding-provider';
import {
	IChaosEnv,
	IChaosEnvOptions,
	IChaosScenario,
	KillSwitch,
	chaosWait,
	recordSchedule,
	runKillPoint,
	settle
} from './helpers/chaos-harness';
import { CHAOS_ENV } from './helpers/chaos-scenarios';

const F1_SATS = 500_000n;
const F2_SATS = 450_000n;
const FLAT_FEE = 1_000;

interface IWorldWallet {
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	wallet: any;
	utxos: Array<{ tx_hash: string; tx_pos: number; value: number }>;
	sentTxs: string[];
	kill: () => KillSwitch | null;
	setKill: (k: KillSwitch) => void;
}

/**
 * A wallet with real freeze bookkeeping and a frozen-aware first-fit coin
 * selection, the shape the real wallet exposes (exclusion happens at
 * selection time; listUtxos does not filter). Wallet writes are gated on
 * the CURRENT life's kill switch: a killed process cannot freeze or build
 * anything, but the durable freeze state survives into the next life,
 * exactly like the real wallet's persisted blacklist.
 */
function makeWorldWallet(values: number[]): IWorldWallet {
	const net = bitcoin.networks.regtest;
	const keySeed = crypto
		.createHash('sha256')
		.update('p7-utxo-wallet-key')
		.digest();
	const ecc = require('@bitcoinerlab/secp256k1');
	bitcoin.initEccLib(ecc);
	const pubkey = Buffer.from(ecc.pointFromScalar(keySeed, true)!);
	const payment = bitcoin.payments.p2wpkh({ pubkey, network: net });

	const fundingTxs = values.map((v) => {
		const tx = new bitcoin.Transaction();
		tx.version = 2;
		tx.addInput(crypto.randomBytes(32), 0);
		tx.addOutput(payment.output!, v);
		return tx;
	});
	const utxos = fundingTxs.map((tx, i) => ({
		tx_hash: tx.getId(),
		tx_pos: 0,
		value: values[i]
	}));

	const frozen = new Map<
		string,
		{ tx_hash: string; tx_pos: number; freezeTag?: string; frozenAt?: number }
	>();
	const sentTxs: string[] = [];
	let killRef: KillSwitch | null = null;
	const sealed = (): boolean => killRef?.killed === true;

	const wallet = {
		network: 'regtest',
		listUtxos: () => utxos,
		isUtxoFrozen: (txid: string, index: number) =>
			frozen.has(`${txid}:${index}`),
		freezeUtxo: async (p: { txid: string; index: number; tag?: string }) => {
			if (sealed()) throw new Error('wallet sealed by the kill');
			frozen.set(`${p.txid}:${p.index}`, {
				tx_hash: p.txid,
				tx_pos: p.index,
				...(p.tag !== undefined
					? { freezeTag: p.tag, frozenAt: Date.now() }
					: {})
			});
			return { isErr: () => false, value: 'frozen' };
		},
		unfreezeUtxo: async (p: { txid: string; index: number }) => {
			if (sealed()) throw new Error('wallet sealed by the kill');
			frozen.delete(`${p.txid}:${p.index}`);
			return { isErr: () => false, value: 'unfrozen' };
		},
		listFrozenUtxos: () => [...frozen.values()],
		electrum: {
			broadcastTransaction: async (p: { rawTx: string }) => ({
				isErr: () => false,
				value: bitcoin.Transaction.fromHex(p.rawTx).getId()
			})
		},
		send: async (params: { address: string; amount: number }) => {
			if (sealed()) throw new Error('wallet sealed by the kill');
			const coin = utxos.find(
				(u) =>
					!frozen.has(`${u.tx_hash}:${u.tx_pos}`) &&
					u.value >= params.amount + FLAT_FEE
			);
			if (!coin) {
				return {
					isErr: () => true,
					error: new Error('insufficient wallet funds')
				};
			}
			const tx = new bitcoin.Transaction();
			tx.version = 2;
			tx.addInput(Buffer.from(coin.tx_hash, 'hex').reverse(), coin.tx_pos);
			tx.addOutput(
				bitcoin.address.toOutputScript(params.address, net),
				params.amount
			);
			const change = coin.value - params.amount - FLAT_FEE;
			if (change > 0) {
				tx.addOutput(payment.output!, change);
			}
			const hex = tx.toHex();
			sentTxs.push(hex);
			return { isErr: () => false, value: hex };
		}
	};

	return {
		wallet,
		utxos,
		sentTxs,
		kill: () => killRef,
		setKill: (k: KillSwitch): void => {
			killRef = k;
		}
	};
}

const inputsOf = (txHex: string): string[] => {
	const tx = bitcoin.Transaction.fromHex(txHex);
	return tx.ins.map(
		(i) => `${Buffer.from(i.hash).reverse().toString('hex')}:${i.index}`
	);
};

interface IS8World {
	world: IWorldWallet;
}

function s8Options(holder: IS8World): IChaosEnvOptions {
	return {
		...CHAOS_ENV,
		victimExtrasFactory: (phase) => {
			void phase;
			return {
				fundingProvider: new WalletFundingProvider(holder.world.wallet as never)
			};
		}
	};
}

function s8FundsFromWallet(holder: IS8World): () => IChaosScenario {
	return (): IChaosScenario => ({
		name: 'S8 wallet-funded open',
		setup(env: IChaosEnv): void {
			holder.world.setKill(env.kill);
		},
		async run(env: IChaosEnv): Promise<void> {
			env.victim.openChannel(env.peers[0].getNodeId(), F1_SATS);
			// The provider flow is asynchronous (fee estimate, wallet build,
			// signing); wait for the funding handshake to finish and every
			// commit to land. Kill-aware: a killed run leaves whatever the
			// schedule says it leaves.
			await chaosWait(
				env,
				() =>
					holder.world.sentTxs.length >= 1 &&
					env.victim
						.getChannelManager()
						.listChannels()
						.some((c) => c.getChannelId() !== null) &&
					env.victim.getRecoveryStatus().awaitingDurabilityCount === 0
			);
			await settle();
		},
		probe(): void {
			// Cell-dependent verdicts; the sweep supplies its own assertions.
		}
	});
}

describe('Recovery phase 7: wallet UTXO selection kills (matrix row 8)', () => {
	it("no kill point lets a second funding select the first funding's coin", async function () {
		this.timeout(300_000);
		const holder: IS8World = { world: makeWorldWallet([700_000, 600_000]) };
		const factory = s8FundsFromWallet(holder);
		const { schedule } = await recordSchedule(
			'local',
			factory,
			s8Options(holder)
		);
		expect(
			schedule.length,
			'the funding flow produced kill labels'
		).to.be.at.least(4);

		let cellsWithRetained = 0;
		let cellsWithFreeze = 0;
		for (const label of schedule) {
			holder.world = makeWorldWallet([700_000, 600_000]);
			const result = await runKillPoint(
				'local',
				factory,
				label,
				s8Options(holder)
			);
			const world = holder.world;
			const at = `at ${label}`;

			// Durable facts the kill left behind.
			const f1Hex = world.sentTxs[0];
			const f1Inputs = f1Hex ? inputsOf(f1Hex) : [];
			const frozenAtKill = world.wallet
				.listFrozenUtxos()
				.map(
					(f: { tx_hash: string; tx_pos: number }) => `${f.tx_hash}:${f.tx_pos}`
				);
			// The node keys retained fundings by INTERNAL byte order (BOLT 2),
			// not the display order getId() returns.
			const f1Txid = f1Hex
				? Buffer.from(bitcoin.Transaction.fromHex(f1Hex).getHash()).toString(
						'hex'
				  )
				: null;
			const retainedJson = result.restoredStorage.loadMetadata?.(
				'pending_funding_txs'
			);

			const retainedOnDisk =
				f1Txid !== null &&
				!!retainedJson &&
				(JSON.parse(retainedJson) as Array<{ txid: string }>).some(
					(r) => r.txid === f1Txid
				);

			// The ordering that makes the row safe: the signed tx is retained
			// on the lightning side only AFTER its inputs were pledged in the
			// wallet, so a durable funding implies a durable freeze.
			if (retainedOnDisk) {
				cellsWithRetained++;
				expect(
					f1Inputs.every((op) => frozenAtKill.includes(op)),
					`funding retained but inputs not pledged ${at}`
				).to.equal(true);
				// A restart that still owes the broadcast must hold the tx.
				const pending = (
					result.restored as unknown as {
						pendingFundingTxs: Map<string, string>;
					}
				).pendingFundingTxs;
				expect(
					pending.has(f1Txid!),
					`retained funding tx survived the restart ${at}`
				).to.equal(true);
			}

			// Fund a second channel from the restarted node (fresh provider,
			// same wallet). Whatever the kill left, F2 must never spend an
			// input of a first funding that exists anywhere durable.
			result.restored.openChannel(result.env.peers[0].getNodeId(), F2_SATS);
			const before = world.sentTxs.length;
			const deadline = Date.now() + 8_000;
			while (world.sentTxs.length === before && Date.now() < deadline) {
				await settle();
			}
			expect(
				world.sentTxs.length,
				`the second funding built its tx ${at}`
			).to.be.greaterThan(before);
			if (frozenAtKill.length > 0) cellsWithFreeze++;
			const f2Inputs = inputsOf(world.sentTxs[world.sentTxs.length - 1]);
			for (const op of f2Inputs) {
				expect(
					frozenAtKill,
					`second funding selected a pledged coin ${at}`
				).to.not.include(op);
				if (retainedOnDisk) {
					expect(
						f1Inputs,
						`second funding double-spent the retained funding ${at}`
					).to.not.include(op);
				}
			}

			result.destroyAll();
		}

		// The sweep only proves the ordering if the interesting states were
		// actually reached: some cell must have died with the funding retained,
		// and some cell with the pledge frozen. A schedule change that empties
		// either bucket has silently stopped testing the row.
		expect(cellsWithRetained, 'cells with a retained funding').to.be.at.least(
			1
		);
		expect(cellsWithFreeze, 'cells with a live pledge').to.be.at.least(1);
	});
});
