import { expect } from 'chai';
import sinon from 'sinon';
import { Transaction } from 'bitcoinjs-lib';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { REGTEST_CHAIN_HASH } from '../../src/lightning/chain/hashes';
import { deriveV2ChannelId } from '../../src/lightning/channel/validation';
import { AssetOpeningCoordinator } from '../../src/lightning/channel/asset-opening-coordinator';
import { AssetOpeningSession } from '../../src/lightning/channel/asset-opening-session';
import type {
	IAuxiliaryDualFunding,
	IAssetOpenDescription
} from '../../src/lightning/channel/asset-opening-provider';
import { sha256 } from '../../src/lightning/crypto/provider';
import { ASSET_OPENING_TYPE_HEX } from '../../src/lightning/features/asset-opening';
import { encodeAssetOpenFrame } from '../../src/lightning/message/asset-open';
import { BeignetCustomSubtype } from '../../src/lightning/message/custom';
import {
	encodeOpenChannel2Message,
	encodeAcceptChannel2Message
} from '../../src/lightning/message/dual-funding';
import { generateFinalDaemonWallet } from '../../src/lightning/storage/final-wallet-generation';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { alice, bob } from './helpers/final-opening-signing';

function terms(deadline: number) {
	const defaults = {
		channelId: Buffer.alloc(32, 5),
		fundingSatoshis: 50000n,
		dustLimitSatoshis: 550n,
		maxHtlcValueInFlightMsat: 25000000n,
		htlcMinimumMsat: 1n,
		toSelfDelay: 6,
		maxAcceptedHtlcs: 20,
		channelType: Buffer.from(ASSET_OPENING_TYPE_HEX, 'hex')
	};
	const points = (p: typeof alice) => ({
		...p.keys.channelBasepoints,
		firstPerCommitmentPoint: Buffer.from(
			p.points.firstPerCommitmentPoint,
			'hex'
		),
		secondPerCommitmentPoint: p.keys.channelBasepoints.paymentBasepoint
	});
	const open = {
		...defaults,
		...points(alice),
		chainHash: REGTEST_CHAIN_HASH,
		fundingFeeratePerkw: 253,
		commitmentFeeratePerkw: 253,
		locktime: 0,
		channelFlags: 0
	};
	const accept = { ...defaults, ...points(bob), minimumDepth: 3 };
	const id = deriveV2ChannelId(
		open.revocationBasepoint,
		accept.revocationBasepoint
	).toString('hex');
	return {
		id,
		start: {
			peer: bob.binding.nodeId,
			initiator: true,
			index: 1,
			deadline,
			open: encodeOpenChannel2Message(open).toString('hex'),
			accept: encodeAcceptChannel2Message(accept).toString('hex')
		}
	};
}

describe('Offline asset opening terms', () => {
	let dir: string, db: SqliteStorage;
	let fresh: ReturnType<typeof generateFinalDaemonWallet>;
	beforeEach(() => {
		fresh = generateFinalDaemonWallet(false, true);
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'asset-opening-terms-'));
		db = SqliteStorage.createFinalWallet(
			path.join(dir, 'wallet.db'),
			fresh.binding
		);
	});
	afterEach(() => {
		db.close();
		fs.rmSync(dir, { recursive: true, force: true });
	});

	it('expires a restored open while its peer stays offline and retires only after wallet release succeeds', async () => {
		const clock = sinon.useFakeTimers({
			toFake: ['setTimeout', 'clearTimeout', 'Date']
		});
		const { id, start } = terms(Date.now() + 700);
		let calls = 0,
			released = false;
		const host = {
			abandon: async () => {
				calls++;
				if (!released) throw new Error('Wallet still starting');
			}
		} as unknown as IAuxiliaryDualFunding;
		db.saveAssetOpenStage(id, 'start', Buffer.from(JSON.stringify(start)));
		db.close();
		db = SqliteStorage.openFinalWallet(
			path.join(dir, 'wallet.db'),
			fresh.binding
		);
		const coordinator = new AssetOpeningCoordinator(
			{ storage: db, root: alice.root },
			host,
			() => {
				throw new Error('No live peer');
			},
			async () => false,
			() => {
				throw new Error('Unexpected opening admission');
			},
			() => undefined
		);
		try {
			await clock.tickAsync(701);
			expect(calls).to.equal(1);
			expect(db.loadAssetOpenStage(id, 'abandoned')).to.deep.equal(
				Buffer.of(1)
			);
			expect(db.listAssetOpenStages()).to.deep.equal([id]);
			released = true;
			await clock.tickAsync(6000);
			expect(calls).to.equal(2);
			expect(db.listAssetOpenStages()).to.deep.equal([]);
		} finally {
			coordinator.destroy();
			clock.restore();
		}
	});

	it('checks the deadline when a host returns even before the expiry timer runs', async () => {
		const now = Date.now(),
			deadline = now + 1000;
		const clock = sinon.useFakeTimers({ now, toFake: ['Date'] });
		const { start } = terms(deadline);
		const host = {
			async propose() {
				clock.setSystemTime(deadline + 1);
				return Buffer.of(1);
			},
			async abandon() {}
		} as unknown as IAuxiliaryDualFunding;
		const sent: Buffer[] = [],
			reasons: string[] = [];
		const session = new AssetOpeningSession(
			start,
			{ storage: db, root: alice.root },
			host,
			(_peer, _type, raw) => sent.push(raw),
			async () => true,
			() => undefined,
			(reason) => reasons.push(reason),
			() => undefined
		);
		try {
			session.begin();
			await new Promise<void>((done) => setImmediate(done));
			expect(sent).to.be.empty;
			expect(reasons).to.deep.equal(['Asset opening approval expired']);
		} finally {
			session.detach();
			clock.restore();
		}
	});

	it('checks each contributors total previous transaction bytes before chain lookups or virtual signatures', async () => {
		const { id, start } = terms(Date.now() + 60000);
		const inputs: IAssetOpenDescription['inputs'] = [];
		for (let i = 0; i < 18; i++) {
			const tx = new Transaction();
			tx.addInput(Buffer.alloc(32, i + 1), 0);
			tx.addOutput(Buffer.alloc(63000), 1000);
			inputs.push({
				serialId: BigInt(i === 1 ? 1 : i * 2),
				txid: tx.getHash(),
				vout: 0,
				sequence: 0xfffffffd,
				prevTx: tx.toBuffer()
			});
		}
		let chain = 0,
			prepare = 0;
		const reasons: string[] = [];
		const host = {
			propose: async () => Buffer.of(1),
			abandon: async () => undefined,
			describe: async () => ({
				inputs,
				outputs: [
					{
						serialId: 98n,
						kind: 'funding',
						valueSats: 100000n,
						descriptorHash: Buffer.alloc(32, 1)
					}
				]
			}),
			prepare: async () => {
				prepare++;
				throw new Error('unexpected signing plan');
			}
		} as unknown as IAuxiliaryDualFunding;
		const session = new AssetOpeningSession(
			start,
			{ storage: db, root: alice.root },
			host,
			() => undefined,
			async () => {
				chain++;
				return true;
			},
			() => undefined,
			(err) => reasons.push(err),
			() => undefined
		);
		try {
			session.begin();
			const layout = Buffer.of(2);
			session.custom(
				BeignetCustomSubtype.ASSET_OPEN,
				encodeAssetOpenFrame({
					attempt: Buffer.from(id, 'hex'),
					phase: 'layout',
					total: 1,
					offset: 0,
					digest: sha256(layout),
					bytes: layout
				})
			);
			await new Promise<void>((done) => setImmediate(done));
			expect(reasons).to.have.length(1);
			expect(chain).to.equal(0);
			expect(prepare).to.equal(0);
		} finally {
			session.detach();
		}
	});
});
