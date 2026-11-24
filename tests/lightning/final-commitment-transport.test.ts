import { expect } from 'chai';
import { MessageType as M } from '../../src/lightning/message/types';
import { FinalCommitmentTransport } from '../../src/lightning/channel/final-commitment-transport';
import type { IFinalOpeningRuntime } from '../../src/lightning/channel/final-opening-runtime';
import { alice } from './helpers/final-opening-signing';

interface ITransportFixture {
	id: string;
	update: Buffer;
	commit: Buffer;
	revoke: Buffer;
	steps: string[];
	transport: FinalCommitmentTransport;
	deliveries: {
		id: bigint;
		direction: 'peer' | 'local';
		type: M;
		payload: Buffer;
	}[];
	loseDepth(): void;
}

function fixture(): ITransportFixture {
	const id = '11'.repeat(32);
	const update = Buffer.from(id, 'hex');
	const commit = Buffer.from('commitment');
	const revoke = Buffer.from('revocation');
	let direction: 'local' | 'peer' = 'peer';
	let staged = false;
	let sentCommit: Buffer | undefined;
	let receivedCommit: Buffer | undefined;
	let ready = true;
	const deliveries: ITransportFixture['deliveries'] = [];
	const steps: string[] = [];
	const runtime = {
		root: alice.root,
		storage: {
			canUpdateFinalCommitments: true,
			loadFinalUpdateStatus: () => ({
				needsPeerCommitment:
					staged && (direction === 'local' || !!receivedCommit) && !sentCommit,
				pending: staged
					? {
							direction,
							type: M.UPDATE_ADD_HTLC,
							payload: update,
							commitmentSigned: sentCommit,
							peerCommitmentSigned: receivedCommit
					  }
					: null
			}),
			stageFinalHtlcUpdate: (_id: string, origin: 'local' | 'peer') => {
				staged = true;
				direction = origin;
				steps.push('stage ' + origin);
			},
			signFinalUpdateCommitmentBatch: () => {
				steps.push('save commitment');
				sentCommit = commit;
				return [commit];
			},
			acceptFinalUpdateCommitmentBatch: () => {
				steps.push('save exit and revocation');
				receivedCommit = commit;
				return revoke;
			},
			acceptFinalUpdateRevocation: () => {
				steps.push('save peer revocation');
				staged = false;
			},
			loadFinalUpdateDeliveries: () => deliveries.slice(),
			ackFinalUpdateDelivery: (_id: string, deliveryId: bigint) => {
				const index = deliveries.findIndex((d) => d.id === deliveryId);
				if (index >= 0) deliveries.splice(index, 1);
			}
		}
	} as unknown as IFinalOpeningRuntime;
	const transport = new FinalCommitmentTransport(
		runtime,
		() => ready,
		(_id, message) => {
			steps.push('send ' + M[message.type]);
		},
		(_id, message) => {
			steps.push('deliver ' + M[message.type]);
		}
	);
	return {
		id,
		update,
		commit,
		revoke,
		steps,
		transport,
		deliveries,
		loseDepth: (): void => {
			ready = false;
		}
	};
}

describe('final commitment transport', () => {
	it('remembers our add and its covering signature before either crosses the wire', () => {
		const f = fixture();
		f.transport.local(f.id, M.UPDATE_ADD_HTLC, f.update);
		expect(f.steps).to.deep.equal([
			'stage local',
			'save commitment',
			'send UPDATE_ADD_HTLC',
			'send COMMITMENT_SIGNED'
		]);
	});

	it('keeps a peer add pending until its commitment arrives, then revokes before signing back', () => {
		const f = fixture();
		f.transport.receive(f.id, { type: M.UPDATE_ADD_HTLC, payload: f.update });
		expect(f.steps).to.deep.equal(['stage peer']);
		f.transport.receive(f.id, { type: M.COMMITMENT_SIGNED, payload: f.commit });
		expect(f.steps.slice(1)).to.deep.equal([
			'save exit and revocation',
			'send REVOKE_AND_ACK',
			'save commitment',
			'send COMMITMENT_SIGNED'
		]);
		f.transport.receive(f.id, { type: M.REVOKE_AND_ACK, payload: f.revoke });
		expect(f.steps[f.steps.length - 1]).to.equal('save peer revocation');
	});

	it('recovers a committed peer settlement offline while leaving a new received add queued', () => {
		const f = fixture();
		f.loseDepth();
		f.deliveries.push(
			{ id: 1n, direction: 'peer', type: M.UPDATE_ADD_HTLC, payload: f.update },
			{
				id: 2n,
				direction: 'peer',
				type: M.UPDATE_FULFILL_HTLC,
				payload: f.update
			}
		);
		f.transport.deliverLocked(f.id, true);
		f.transport.deliverLocked(f.id, true);
		expect(f.steps).to.deep.equal(['deliver UPDATE_FULFILL_HTLC']);
		expect(f.deliveries.map((d) => d.id)).to.deep.equal([1n]);
	});

	it('withholds new wallet and peer signatures while live funding depth is missing', () => {
		const f = fixture();
		f.loseDepth();
		expect(() =>
			f.transport.local(f.id, M.UPDATE_ADD_HTLC, f.update)
		).to.throw();
		expect(() =>
			f.transport.receive(f.id, {
				type: M.COMMITMENT_SIGNED,
				payload: f.commit
			})
		).to.throw();
		expect(f.steps).to.deep.equal([]);
	});
});
