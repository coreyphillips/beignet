import { expect } from 'chai';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { FinalOpeningTransport } from '../../src/lightning/channel/final-opening-transport';
import type { IFundingProvider } from '../../src/lightning/node/types';
import { MessageType } from '../../src/lightning/message/types';
import {
	decodeChannelReestablishMessage,
	encodeChannelReestablishMessage
} from '../../src/lightning/message/channel-reestablish';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { alice, bob, signingFixture } from './helpers/final-opening-signing';

describe('Final opening transport across backend and peer outages', () => {
	let dir: string;
	let a: SqliteStorage, b: SqliteStorage;
	beforeEach(() => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-final-peer-replay-'));
		a = SqliteStorage.createFinalWallet(path.join(dir, 'a.db'), alice.binding);
		b = SqliteStorage.createFinalWallet(path.join(dir, 'b.db'), bob.binding);
	});
	afterEach(() => {
		a.close();
		b.close();
		fs.rmSync(dir, { recursive: true, force: true });
	});
	function prepared(): ReturnType<typeof signingFixture> {
		const f = signingFixture();
		const { id, candidate, terms, counterpart } = f;
		a.allocateFinalChannelKeyIndex(alice.index);
		b.allocateFinalChannelKeyIndex(bob.index);
		a.rememberFinalOpeningSession(
			candidate,
			bob.binding.nodeId,
			terms,
			alice.index
		);
		b.rememberFinalOpeningSession(
			counterpart.candidate,
			alice.binding.nodeId,
			counterpart.terms,
			bob.index
		);
		const ours = a.finalOpeningTxComplete(id, alice.keys.fundingPrivkey);
		const theirs = b.finalOpeningTxComplete(id, bob.keys.fundingPrivkey);
		a.rememberFinalPeerTxComplete(id, theirs);
		b.rememberFinalPeerTxComplete(id, ours);
		return f;
	}
	function offline(): {
		transport: FinalOpeningTransport;
		sent: MessageType[];
		refused: string[];
	} {
		const sent: MessageType[] = [],
			refused: string[] = [];
		const wallet = {
			resolveFinalOpeningInputs: async () => {
				throw Error(
					'No wallet funding signature is authorized during chain outage'
				);
			}
		} as unknown as IFundingProvider;
		const transport = new FinalOpeningTransport(
			{ storage: a, root: alice.root },
			async () => {
				throw Error('Synthetic chain backend outage');
			},
			() => wallet,
			(_peer, type) => sent.push(type),
			() => {
				throw Error('Unexpected funding broadcast');
			},
			(_id, message) => refused.push(message)
		);
		return { transport, sent, refused };
	}
	it('retains an already promised peer commitment through a chain outage without releasing our funding inputs', async () => {
		const { id, terms, counterpart } = prepared();
		a.signFinalPeerCommitment(id, terms, alice.root, alice.index);
		const peer = b.signFinalPeerCommitment(
			id,
			counterpart.terms,
			bob.root,
			bob.index
		);
		const { transport, sent } = offline();
		transport.queue(bob.binding.nodeId, id, {
			type: MessageType.COMMITMENT_SIGNED,
			payload: peer
		});
		await new Promise<void>((done) => setImmediate(done));
		expect(sent).not.to.include(MessageType.TX_SIGNATURES);
		expect(a.loadFinalLocalTxSignatures(id)).to.equal(null);
		expect(
			a.loadFinalOpeningExit(id),
			'retain verified exit from the peer share already received'
		).to.be.instanceOf(Buffer);
	});

	it('resumes both original wallets after simultaneous restart at the saved nonce boundary', async () => {
		const { id } = prepared();
		const before = [
			a.loadFinalLocalTxComplete(id),
			b.loadFinalLocalTxComplete(id)
		];
		a.close();
		b.close();
		a = SqliteStorage.openFinalWallet(path.join(dir, 'a.db'), alice.binding);
		b = SqliteStorage.openFinalWallet(path.join(dir, 'b.db'), bob.binding);
		const sent: Array<{ peer: string; type: MessageType; payload: Buffer }> =
			[];
		const refused: string[] = [];
		const build = (
			store: SqliteStorage,
			side: typeof alice
		): FinalOpeningTransport =>
			new FinalOpeningTransport(
				{ storage: store, root: side.root },
				async () => 'unspent',
				() =>
					({
						resolveFinalOpeningInputs: async () => () => {
							throw Error('Unexpected funding witness');
						}
					}) as unknown as IFundingProvider,
				(peer, type, payload) => {
					sent.push({ peer, type, payload });
				},
				() => {
					throw Error('Unexpected broadcast');
				},
				(_id, reason) => refused.push(reason)
			);
		const A = build(a, alice),
			B = build(b, bob);
		const deliver = async (type: MessageType): Promise<void> => {
			const batch = sent.splice(0);
			expect(batch.map((msg) => msg.type)).to.deep.equal([type, type]);
			for (const msg of batch) {
				const toAlice = msg.peer === alice.binding.nodeId;
				(toAlice ? A : B).queue(
					toAlice ? bob.binding.nodeId : alice.binding.nodeId,
					id,
					msg
				);
			}
			await new Promise<void>((done) => setImmediate(done));
		};
		A.reconnected(bob.binding.nodeId);
		B.reconnected(alice.binding.nodeId);
		for (const message of sent) {
			const reestablish = decodeChannelReestablishMessage(message.payload, {
				finalTaproot: true
			});
			expect(reestablish.nextCommitmentNumber).to.equal(1n);
			expect(reestablish.nextFundingRetransmitFlags).to.equal(1);
			expect(reestablish.currentCommitNonce).to.be.instanceOf(Buffer);
		}
		await deliver(MessageType.CHANNEL_REESTABLISH);
		expect(sent.map((msg) => msg.payload.toString('hex'))).to.have.members(
			before.map((raw) => raw!.toString('hex'))
		);
		await deliver(MessageType.TX_COMPLETE);
		expect(refused).to.deep.equal([]);
		expect(sent.map((msg) => msg.type)).to.deep.equal([
			MessageType.COMMITMENT_SIGNED,
			MessageType.COMMITMENT_SIGNED
		]);
		expect(a.loadFinalPeerCommitment(id)).to.deep.equal(
			sent.find((msg) => msg.peer === bob.binding.nodeId)!.payload
		);
		expect(b.loadFinalPeerCommitment(id)).to.deep.equal(
			sent.find((msg) => msg.peer === alice.binding.nodeId)!.payload
		);
		expect(a.loadFinalLocalTxSignatures(id)).to.equal(null);
		expect(b.loadFinalLocalTxSignatures(id)).to.equal(null);
	});

	it('refuses reestablish omitting its promised next nonce before replaying any saved shares', async () => {
		const { id, funding, terms } = prepared();
		a.signFinalPeerCommitment(id, terms, alice.root, alice.index);
		const { transport, sent, refused } = offline();
		const missingNonce = encodeChannelReestablishMessage({
			channelId: Buffer.from(id, 'hex'),
			nextCommitmentNumber: 1n,
			nextRevocationNumber: 0n,
			yourLastPerCommitmentSecret: Buffer.alloc(32),
			myCurrentPerCommitmentPoint: Buffer.from(
				terms.remoteBasepoints.firstPerCommitmentPoint,
				'hex'
			),
			nextFundingTxid: funding.getHash(),
			nextFundingRetransmitFlags: 0
		});
		transport.queue(bob.binding.nodeId, id, {
			type: MessageType.CHANNEL_REESTABLISH,
			payload: missingNonce
		});
		await new Promise<void>((done) => setImmediate(done));
		expect(sent).to.be.empty;
		expect(refused).to.have.length(1);
	});
});
