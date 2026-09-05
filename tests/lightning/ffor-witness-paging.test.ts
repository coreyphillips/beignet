/**
 * Appendix F.1 paging (ffor #33): a mailbox can hold more records than one
 * ff_witness_fetch_resp carries, so W serves them in ascending k pages, each
 * page a fresh fetch under a fresh nonce naming after_k, and names
 * next_after_k while records remain. R walks the pages until the witness
 * names none. A witness that pages backwards is stopped, and what it served
 * is still verified and credited.
 */

import { expect } from 'chai';
import { PaymentStatus } from '../../src/lightning/node/types';
import { decode as decodeInvoice } from '../../src/lightning/invoice/decode';
import {
	FF_WITNESS_FETCH_RESP_TYPE,
	FF_WITNESS_FETCH_TYPE
} from '../../src/lightning/ffor/witness-types';
import {
	decodeWitnessFetch,
	decodeWitnessFetchResp,
	encodeWitnessFetchResp
} from '../../src/lightning/ffor/witness-messages';
import { activate, record } from './helpers/ffor-world';
import {
	IWitnessWorld,
	createWitnessWorld,
	waitFor
} from './helpers/ffor-witness-world';

/** Three slots exposed and paid through W with R offline: three records. */
async function threeRecords(w: IWitnessWorld): Promise<string> {
	activate(w, { witnessPeers: [Buffer.from(w.w.getNodeId(), 'hex')] });
	await w.r.provisionFforWitness(w.srHex, w.w.getNodeId());
	const invoices = [1, 2, 3].map(
		(k) => w.r.createFforVoucherInvoice(w.srHex, k).bolt11
	);
	w.sr.disconnect();
	for (const bolt11 of invoices) {
		const hash = decodeInvoice(bolt11).paymentHash;
		w.p.sendPayment(bolt11);
		await waitFor(
			() => w.p.getPayment(hash)?.status === PaymentStatus.COMPLETED,
			`payment ${hash.toString('hex').slice(0, 8)}`
		);
	}
	const mailboxIdHex = record(w.r, w.srHex).witnesses[0].mailboxId.toString(
		'hex'
	);
	expect(
		w.w.getFforWitnessService()!.ledger.listRecords(mailboxIdHex)
	).to.have.length(3);
	w.rw.log.length = 0;
	return mailboxIdHex;
}

function fetches(w: IWitnessWorld): ReturnType<typeof decodeWitnessFetch>[] {
	return w.rw
		.sentBy(w.r)
		.filter((e) => e.type === FF_WITNESS_FETCH_TYPE)
		.map((e) => decodeWitnessFetch(e.payload));
}

function responses(
	w: IWitnessWorld
): ReturnType<typeof decodeWitnessFetchResp>[] {
	return w.rw
		.sentBy(w.w)
		.filter((e) => e.type === FF_WITNESS_FETCH_RESP_TYPE)
		.map((e) => decodeWitnessFetchResp(e.payload));
}

describe('FFOR receipt witness: fetch paging (Appendix F.1)', function () {
	this.timeout(60_000);

	it('a page holds one record: three pages, three fresh nonces, every record credited', async () => {
		const w = createWitnessWorld({ fetchPageBytes: 1 });
		await threeRecords(w);
		const fetched = await w.r.fetchFforWitnessRecords(w.srHex);
		expect(fetched).to.have.length(1);
		expect(fetched[0].ok).to.be.true;
		expect(fetched[0].records.map((r) => [r.k, r.verified])).to.deep.equal([
			[1, true],
			[2, true],
			[3, true]
		]);
		expect(fetched[0].credited).to.equal(3);
		for (let k = 0; k < 3; k++) {
			expect(
				record(w.r, w.srHex).knownPreimages[k]!.equals(
					record(w.s, w.srHex).preimages[k]!
				)
			).to.be.true;
		}
		const sent = fetches(w);
		expect(sent.map((f) => f.afterK)).to.deep.equal([undefined, 1, 2]);
		expect(new Set(sent.map((f) => f.nonce.toString('hex'))).size).to.equal(3);
		expect(
			responses(w).map((r) => [r.records.length, r.nextAfterK])
		).to.deep.equal([
			[1, 1],
			[1, 2],
			[1, undefined]
		]);
		w.wStorage.close();
	});

	it('records that fit one page answer in one message with no next page', async () => {
		const w = createWitnessWorld();
		await threeRecords(w);
		const fetched = await w.r.fetchFforWitnessRecords(w.srHex);
		expect(fetched[0].ok).to.be.true;
		expect(fetched[0].credited).to.equal(3);
		expect(fetches(w)).to.have.length(1);
		expect(fetches(w)[0].afterK).to.equal(undefined);
		expect(responses(w)).to.have.length(1);
		expect(responses(w)[0].records).to.have.length(3);
		expect(responses(w)[0].nextAfterK).to.equal(undefined);
		w.wStorage.close();
	});

	it('a witness that pages backwards is stopped after the second page, and what it served is credited', async () => {
		const w = createWitnessWorld({ fetchPageBytes: 1 });
		await threeRecords(w);
		// Every page names k = 1 as the next page, whatever it served.
		const svc = w.w.getFforWitnessService()! as unknown as {
			deps: { send: (peer: string, type: number, payload: Buffer) => void };
		};
		const send = svc.deps.send;
		svc.deps.send = (peer, type, payload): void => {
			if (type === FF_WITNESS_FETCH_RESP_TYPE) {
				const m = decodeWitnessFetchResp(payload);
				if (m.ok && m.records.length > 0) {
					payload = encodeWitnessFetchResp({ ...m, nextAfterK: 1 });
				}
			}
			send(peer, type, payload);
		};
		const fetched = await w.r.fetchFforWitnessRecords(w.srHex);
		expect(fetched[0].ok).to.be.false;
		expect(fetched[0].error).to.equal('witness paged backwards');
		expect(fetched[0].records.map((r) => r.k)).to.deep.equal([1, 2]);
		expect(fetched[0].credited).to.equal(2);
		expect(fetches(w).map((f) => f.afterK)).to.deep.equal([undefined, 1]);
		w.wStorage.close();
	});
});
