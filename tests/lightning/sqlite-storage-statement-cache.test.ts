/**
 * SqliteStorage prepares each fixed SQL string once per instance (issue
 * #1680). Only SQL assembled per call is prepared again.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import Database from 'better-sqlite3';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { IStoredRecoveryFrame } from '../../src/lightning/storage/types';
import {
	RecoveryCriticality,
	RecoveryJournal,
	RecoveryManager,
	deriveRecoveryMasterKey,
	deriveRecoveryRoot
} from '../../src/lightning/recovery';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import {
	DEFAULT_CHANNEL_CONFIG,
	ChannelState
} from '../../src/lightning/channel/types';
import {
	IChannelState,
	createOpenerState
} from '../../src/lightning/channel/channel-state';
import { MessageType } from '../../src/lightning/message/types';
import {
	IPaymentInfo,
	PaymentDirection,
	PaymentStatus
} from '../../src/lightning/node/types';

function seed(id: number): Buffer {
	return crypto.createHash('sha256').update(`stmt-cache-${id}`).digest();
}

function basepoints(base: Buffer): IChannelBasepoints {
	const key = (i: number): Buffer =>
		getPublicKey(
			crypto
				.createHash('sha256')
				.update(base)
				.update(Buffer.from([i]))
				.digest()
		);
	return {
		fundingPubkey: key(0),
		revocationBasepoint: key(1),
		paymentBasepoint: key(2),
		delayedPaymentBasepoint: key(3),
		htlcBasepoint: key(4),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

function channelState(channelId: Buffer, balance: bigint): IChannelState {
	const state = createOpenerState({
		temporaryChannelId: crypto.createHash('sha256').update(channelId).digest(),
		fundingSatoshis: 1_000_000n,
		pushMsat: 0n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: basepoints(seed(1)),
		localPerCommitmentSeed: seed(3)
	});
	state.state = ChannelState.NORMAL;
	state.channelId = channelId;
	state.fundingTxid = crypto.createHash('sha256').update(channelId).digest();
	state.fundingOutputIndex = 0;
	state.localBalanceMsat = balance;
	state.remoteBalanceMsat = 1_000_000_000n - balance;
	state.remoteBasepoints = basepoints(seed(2));
	state.remoteCurrentPerCommitmentPoint =
		state.remoteBasepoints.firstPerCommitmentPoint;
	return state;
}

function payment(hash: Buffer, createdAt: number): IPaymentInfo {
	return {
		paymentHash: hash,
		amountMsat: 1000n,
		status: PaymentStatus.COMPLETED,
		direction: PaymentDirection.OUTGOING,
		createdAt
	} as IPaymentInfo;
}

const NODE_SECRET = seed(9);
const PEER = 'aa'.repeat(33);
const CHANNEL_ID = seed(4);

describe('SqliteStorage statement cache', () => {
	let storage: SqliteStorage;
	/** The SQL of every db.prepare call since open. */
	let prepared: string[];

	beforeEach(() => {
		storage = new SqliteStorage(':memory:');
		storage.open();
		const db = (storage as unknown as { db: Database.Database }).db;
		const prepare = db.prepare.bind(db);
		prepared = [];
		db.prepare = ((sql: string) => {
			prepared.push(sql);
			return prepare(sql);
		}) as typeof db.prepare;
	});

	afterEach(() => {
		storage.close();
	});

	/** The SQL db.prepare compiled while fn ran. */
	function preparedDuring(fn: () => void): string[] {
		const before = prepared.length;
		fn();
		return prepared.slice(before);
	}

	it('prepares only the SQL built per call when a hot path runs again', () => {
		const journal = new RecoveryJournal(
			storage,
			deriveRecoveryMasterKey(NODE_SECRET),
			getPublicKey(NODE_SECRET),
			deriveRecoveryRoot(NODE_SECRET).recoveryId
		);
		const manager = new RecoveryManager(storage, { journal });
		const idHex = CHANNEL_ID.toString('hex');
		for (let i = 0; i < 5; i++) {
			const hash = seed(100 + i);
			storage.savePayment(hash.toString('hex'), payment(hash, 1_700_000 + i));
		}
		let n = 0;
		const commit = (): void => {
			n++;
			const result = manager.commit({
				criticality: RecoveryCriticality.SafetyCritical,
				mutations: [
					{
						type: 'channel_state',
						channelId: idHex,
						state: channelState(CHANNEL_ID, 200_000_000n + BigInt(n)),
						peerPubkey: PEER
					},
					{ type: 'channel_key_index', channelId: idHex, channelIndex: 1 }
				],
				outboundMessages: [
					{
						peerId: PEER,
						channelId: idHex,
						messageType: MessageType.COMMITMENT_SIGNED,
						wireMessage: seed(200 + n),
						disposition: 'pending_send'
					}
				]
			});
			expect(result.committed).to.equal(true);
		};
		// The first journaled commit writes a snapshot, not a delta frame.
		commit();
		const round = (): void => {
			storage.saveChannel(
				idHex,
				channelState(CHANNEL_ID, 100_000_000n + BigInt(n)),
				PEER
			);
			commit();
			let loaded = 0;
			for (const ref of storage.paymentsNewestFirst()) {
				if (ref.load()) loaded++;
			}
			expect(loaded).to.equal(5);
		};

		round();
		// The outbox stamp's IN list and the payments page's key batch.
		const again = preparedDuring(round);
		expect(again).to.have.lengthOf(2);
		expect(again[0]).to.match(
			/^UPDATE recovery_outbox SET frame_sequence = \?\s+WHERE id IN \(\?\)$/
		);
		expect(again[1]).to.match(
			/^SELECT payment_hash, created_at FROM payments WHERE /
		);
	});

	it('runs a statement again after it threw', () => {
		const frame = (sequence: number): IStoredRecoveryFrame => ({
			sequence,
			writerEpoch: 1,
			frameHash: seed(300 + sequence),
			previousFrameHash: seed(299 + sequence),
			ciphertext: seed(400 + sequence),
			createdAt: 1_700_000
		});
		storage.saveRecoveryFrame(frame(1));
		expect(() => storage.saveRecoveryFrame(frame(1))).to.throw(
			/UNIQUE constraint failed/
		);
		const written = preparedDuring(() => storage.saveRecoveryFrame(frame(2)));
		expect(written).to.deep.equal([]);
		expect(storage.loadRecoveryFrame(2)?.ciphertext).to.deep.equal(
			frame(2).ciphertext
		);
	});
});
