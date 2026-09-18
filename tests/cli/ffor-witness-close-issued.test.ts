/**
 * The witness close and the issuer's issued slots through the methods the
 * daemon routes call (issue #882): POST /ffor/witness/close and
 * GET /ffor/issuer/issued. R, S and the witness are real nodes on loopback
 * links.
 */

import { expect } from 'chai';
import { BeignetNode } from '../../src/cli/beignet-node';
import { BeignetError } from '../../src/cli/errors';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	IWorld,
	NodeLink,
	TIP,
	activate,
	createWorld,
	makeNodeConfig,
	record
} from '../lightning/helpers/ffor-world';

/** A BeignetNode over the given engine; the prototype keeps helpers resolvable. */
function cliOver(engine: LightningNode): BeignetNode {
	return Object.assign(Object.create(BeignetNode.prototype), {
		node: engine
	}) as unknown as BeignetNode;
}

async function refusal(call: Promise<unknown>): Promise<BeignetError> {
	try {
		await call;
	} catch (err: unknown) {
		expect(err).to.be.instanceOf(BeignetError);
		return err as BeignetError;
	}
	expect.fail('expected the call to throw');
}

let seed = 8820;

/** An ACTIVE epoch on S-R with one acknowledged witness (and issuer) W. */
async function witnessedEpoch(): Promise<{
	w: IWorld;
	witness: LightningNode;
	mailboxIdHex: string;
}> {
	const w = createWorld();
	seed += 1;
	const witness = new LightningNode(
		makeNodeConfig(seed, undefined, {
			fforWitness: { enabled: true },
			fforIssuer: { enabled: true }
		})
	);
	witness.on('node:error', () => {});
	new NodeLink(w.r, witness);
	witness.handleNewBlock(TIP);
	activate(w);
	const { mailboxId } = await w.r.provisionFforWitness(
		w.srHex,
		witness.getNodeId()
	);
	return { w, witness, mailboxIdHex: mailboxId.toString('hex') };
}

function mailboxState(witness: LightningNode): string {
	return witness.getFforWitnessService()!.listMailboxes()[0].state;
}

describe('FFOR witness close and issued slots (issue #882)', function () {
	this.timeout(30_000);

	it('closes every witness once ff_close_ack is in, and refuses before it', async () => {
		const { w, witness } = await witnessedEpoch();
		const cli = cliOver(w.r);

		// While ACTIVE a closed witness would stop recording this book's
		// payments, so nothing is sent.
		const early = await refusal(cli.fforCloseWitnesses(w.srHex));
		expect(early.code).to.equal('FFOR_REFUSED');
		expect(early.message).to.match(/ff_close_ack/);
		expect(mailboxState(witness)).to.equal('PROVISIONED');

		// S's record is no receiver's epoch.
		const settler = await refusal(cliOver(w.s).fforCloseWitnesses(w.srHex));
		expect(settler.code).to.equal('NOT_FOUND');

		expect(w.r.closeFforEpoch(w.srHex).ok).to.equal(true);
		expect(record(w.r, w.srHex).settledBitmap).to.not.equal(null);
		const closed = await cli.fforCloseWitnesses(w.srHex);
		expect(closed).to.deep.equal([
			{ witnessNodeId: witness.getNodeId(), ok: true, held: 0 }
		]);
		expect(mailboxState(witness)).to.equal('CLOSED');
	});

	it("reads the issuer's issued slots, with payer, metadata and time", async () => {
		const { w, witness, mailboxIdHex } = await witnessedEpoch();
		const { offer } = w.r.createFforIssuerOffer(witness.getNodeId(), {
			description: 'ffor slots'
		});
		await w.r.provisionFforIssuer(w.srHex, witness.getNodeId(), {
			offer,
			witnessHops: []
		});
		const cli = cliOver(w.r);

		const none = await cli.fforIssuedSlots(w.srHex, witness.getNodeId());
		expect(none).to.deep.equal({
			ok: true,
			numSlots: 3,
			issued: '00',
			slots: [],
			error: null
		});

		// The issuer's own durable step when it answers a request for slot 2.
		const ledger = witness.getFforIssuerService()!.ledger;
		const slot2 = ledger.slotsOf(mailboxIdHex)[1];
		const payerIdHex = '02' + 'aa'.repeat(32);
		const metadataHashHex = 'bb'.repeat(32);
		expect(
			ledger.issue(slot2.id, payerIdHex, metadataHashHex).outcome
		).to.equal('applied');
		const issuedAt = ledger.slotsOf(mailboxIdHex)[1].issuedUnixTime;

		const one = await cli.fforIssuedSlots(
			w.srHex,
			witness.getNodeId().toUpperCase()
		);
		expect(one).to.deep.equal({
			ok: true,
			numSlots: 3,
			// Bit k-1 of byte 0, LSB first.
			issued: '02',
			slots: [
				{
					k: 2,
					payerId: payerIdHex,
					metadataHash: metadataHashHex,
					issuedUnixTime: issuedAt
				}
			],
			error: null
		});
	});

	it('refuses a malformed or unprovisioned issuer', async () => {
		const { w } = await witnessedEpoch();
		const cli = cliOver(w.r);
		const malformed = await refusal(cli.fforIssuedSlots(w.srHex, 'not-a-key'));
		expect(malformed.code).to.equal('INVALID_PARAMS');
		const stranger = await refusal(
			cli.fforIssuedSlots(w.srHex, w.p.getNodeId())
		);
		expect(stranger.code).to.equal('FFOR_REFUSED');
		expect(stranger.message).to.match(/no such witness provision/);
	});
});
