import { expect } from 'chai';
import { Transaction } from 'bitcoinjs-lib';
import { MessageType } from '../../src/lightning/message/types';
import {
	driveFinalSimpleClose,
	type IFinalSimpleCloseState,
	type IFinalCloseRequest
} from '../../src/lightning/storage/final-simple-close';
import type { FinalOpeningAuthority } from '../../src/lightning/storage/final-opening-authority';
import { alice, bob, signingFixture } from './helpers/final-opening-signing';

interface IClosePeer {
	step(
		input: Partial<IFinalCloseRequest>,
		pending?: boolean
	): ReturnType<typeof driveFinalSimpleClose>;
	saved(): IFinalSimpleCloseState;
}

function closePair(): { a: IClosePeer; b: IClosePeer } {
	const { id, candidate, terms, counterpart } = signingFixture();
	const make = (
		local: typeof alice,
		view: typeof counterpart,
		peer: typeof alice
	): IClosePeer => {
		let state: IFinalSimpleCloseState = {};
		const claims = new Map<string, { transcript: string; result?: Buffer }>();
		const authority: Partial<FinalOpeningAuthority> = {
			claim(slot, transcript) {
				const prior = claims.get(slot);
				if (prior && prior.transcript !== transcript)
					throw Error('Conflicting device claim');
				if (!prior) claims.set(slot, { transcript });
				return prior?.result ?? null;
			},
			finish(slot, transcript, result) {
				if (claims.get(slot)?.transcript !== transcript)
					throw Error('Missing claim');
				claims.set(slot, { transcript, result });
				return result;
			},
			commitLifecycleEntry(slot, transcript) {
				if (claims.has(slot) && claims.get(slot)!.transcript !== transcript)
					throw Error('Conflicting close');
				claims.set(slot, { transcript });
			}
		};
		const script = Buffer.from(
			'0014' + (local === alice ? '11' : '22').repeat(20),
			'hex'
		);
		const snapshot = {
			localHeight: 2n,
			remoteHeight: 2n,
			localBalanceMsat: 1000n * BigInt(view.candidate.localContributionSats),
			remoteBalanceMsat: 1000n * BigInt(view.candidate.remoteContributionSats),
			pending: null,
			htlcs: []
		};
		function step(
			input: Partial<IFinalCloseRequest>,
			pending = false
		): ReturnType<typeof driveFinalSimpleClose> {
			const next = JSON.parse(JSON.stringify(state)) as IFinalSimpleCloseState;
			const res = driveFinalSimpleClose(
				id,
				{ ...view.candidate, localFundingKeyIndex: local.index },
				{
					session: {
						peer: peer.binding.nodeId,
						terms: view.terms,
						channelKeyIndex: local.index
					}
				},
				Buffer.alloc(32, local.index),
				authority as FinalOpeningAuthority,
				local.root,
				JSON.stringify([2, local.binding.nodeId, 'regtest']),
				next,
				{ ...snapshot, pending: pending ? {} : null },
				{ script, blockHeight: 101, feeratePerKw: 1000, ...input }
			);
			state = next;
			return res;
		}
		return {
			step,
			saved: (): IFinalSimpleCloseState =>
				JSON.parse(JSON.stringify(state)) as IFinalSimpleCloseState
		};
	};
	return {
		a: make(alice, { candidate, terms }, bob),
		b: make(bob, counterpart, alice)
	};
}

describe('final simple close transcript', () => {
	it('finishes crossed close proposals with each participant paying its own proposed fee and replays a saved response', () => {
		const { a, b } = closePair();
		const [aShutdown] = a.step({ start: true }).messages;
		const [bShutdown, bProposal] = b.step({ message: aShutdown }).messages;
		const [aProposal] = a.step({ message: bShutdown }).messages;
		const aResponse = a.step({ message: bProposal });
		const bResponse = b.step({ message: aProposal });
		expect(b.step({ message: aProposal })).to.deep.equal(bResponse);
		expect(
			a.step({ message: bResponse.messages[0] }).transaction
		).to.deep.equal(bResponse.transaction);
		expect(
			b.step({ message: aResponse.messages[0] }).transaction
		).to.deep.equal(aResponse.transaction);
		expect(aResponse.messages[0].type).to.equal(MessageType.CLOSING_SIG);
		expect(
			Transaction.fromBuffer(aResponse.transaction!).ins[0].witness[0].length
		).to.equal(64);
		expect(a.saved().peerTransaction).to.equal(
			aResponse.transaction!.toString('hex')
		);
	});

	it('remembers a requested destination before shutdown and waits for an unsigned update to clear', () => {
		const { a } = closePair();
		expect(a.step({ start: true }, true).messages).to.deep.equal([]);
		expect(a.saved().requestedScript).to.be.a('string');
		expect(a.saved().locked).to.equal(undefined);
		expect(a.step({}).messages.map((m) => m.type)).to.deep.equal([
			MessageType.SHUTDOWN
		]);
	});
});
