/**
 * The receipt witness's durable store (spec Appendix F.5; issue #720 M9.0):
 * a mailbox survives a restart with R offline and serves from disk, the
 * hash index is rebuilt at rehydration, a fetch nonce accepted before the
 * restart is still refused after it, and capacity is judged against what
 * the ledger holds.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { MetadataLedgerStore } from '../../src/lightning/storage/durable-ledger';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { FforVariant, IFforBookEntry } from '../../src/lightning/ffor/types';
import {
	buildVoucherBook,
	computeHAct,
	computeHBook
} from '../../src/lightning/ffor/transcript';
import {
	decodeWitnessAck,
	decodeWitnessFetchResp,
	encodeWitnessFetch,
	encodeWitnessProvision,
	signManifest
} from '../../src/lightning/ffor/witness-messages';
import {
	FF_WITNESS_ACK_TYPE,
	FF_WITNESS_FETCH_RESP_TYPE,
	FF_WITNESS_FETCH_TYPE,
	FF_WITNESS_PROFILE_DR,
	FF_WITNESS_PROVISION_TYPE,
	FF_WITNESS_VERSION
} from '../../src/lightning/ffor/witness-types';
import {
	FF_WITNESS_MAILBOX_LEDGER_PREFIX,
	FF_WITNESS_RECORD_LEDGER_PREFIX,
	FforWitnessLedger,
	IFforWitnessMailboxRecord,
	IFforWitnessRecordRow,
	fforWitnessMailboxCodec,
	fforWitnessRecordCodec
} from '../../src/lightning/ffor/witness-ledger';
import {
	FforWitnessService,
	IFforWitnessConfig
} from '../../src/lightning/ffor/witness-service';

const sha256 = (b: Buffer): Buffer =>
	crypto.createHash('sha256').update(b).digest();
const W_PRIV = sha256(Buffer.from('witness-node'));
const W_ID = getPublicKey(W_PRIV);

function ledgerOn(storage: SqliteStorage): FforWitnessLedger {
	const ledger = new FforWitnessLedger(
		new MetadataLedgerStore<IFforWitnessMailboxRecord>(
			storage,
			FF_WITNESS_MAILBOX_LEDGER_PREFIX,
			fforWitnessMailboxCodec
		),
		new MetadataLedgerStore<IFforWitnessRecordRow>(
			storage,
			FF_WITNESS_RECORD_LEDGER_PREFIX,
			fforWitnessRecordCodec
		)
	);
	ledger.rehydrate();
	return ledger;
}

interface IHarness {
	service: FforWitnessService;
	sent: { peer: string; type: number; payload: Buffer }[];
	events: { event: string; data: unknown }[];
}

function serviceOn(
	ledger: FforWitnessLedger,
	cfg: Partial<IFforWitnessConfig> = {}
): IHarness {
	const sent: IHarness['sent'] = [];
	const events: IHarness['events'] = [];
	const service = new FforWitnessService(
		{ enabled: true, ...cfg },
		{
			ledger,
			nodePrivkey: W_PRIV,
			nodeId: W_ID,
			currentHeight: () => 790_100,
			send: (peer, type, payload) => sent.push({ peer, type, payload }),
			log: () => undefined,
			emit: (event, data) => events.push({ event, data })
		}
	);
	return { service, sent, events };
}

function book(
	K: number,
	seed = 'book'
): { book: Buffer; entries: IFforBookEntry[] } {
	const entries = Array.from({ length: K }, (_, i) => ({
		k: i + 1,
		paymentHash: sha256(Buffer.from(`${seed}-${i}`)),
		amountMsat: 100_000_000n,
		voucherExpiry: 800_000,
		settlementDeadline: 798_992,
		sHtlcId: BigInt(i)
	}));
	return {
		book: buildVoucherBook(sha256(Buffer.from(seed)), FforVariant.D, entries),
		entries
	};
}

interface IProvision {
	wire: Buffer;
	mailboxId: Buffer;
	fetchPriv: Buffer;
}

function provisionFor(
	bookBytes: Buffer,
	tweak: Record<string, unknown> = {}
): IProvision {
	const fetchPriv = crypto.randomBytes(32);
	const mailboxId = crypto.randomBytes(32);
	const tSetup = crypto.randomBytes(32);
	const hCommit = crypto.randomBytes(32);
	const wire = signManifest(
		{
			version: FF_WITNESS_VERSION,
			profile: FF_WITNESS_PROFILE_DR,
			mailboxId,
			tSetup,
			hCommit,
			epochStartHeight: 790_000,
			hAct: computeHAct(tSetup, computeHBook(bookBytes), hCommit, 790_000),
			fetchPubkey: getPublicKey(fetchPriv),
			encPubkey: getPublicKey(crypto.randomBytes(32)),
			retentionUntil: 800_200,
			minReceipts: 0,
			book: bookBytes,
			...tweak
		},
		fetchPriv
	);
	return { wire, mailboxId, fetchPriv };
}

function provision(
	h: IHarness,
	p: IProvision
): ReturnType<typeof decodeWitnessAck> {
	const before = h.sent.length;
	h.service.handleMessage(
		'peer',
		FF_WITNESS_PROVISION_TYPE,
		encodeWitnessProvision(crypto.randomBytes(16), p.wire)
	);
	const reply = h.sent[before];
	expect(reply.type).to.equal(FF_WITNESS_ACK_TYPE);
	return decodeWitnessAck(reply.payload);
}

function fetch(
	h: IHarness,
	p: IProvision,
	nonce = crypto.randomBytes(32)
): ReturnType<typeof decodeWitnessFetchResp> {
	const before = h.sent.length;
	h.service.handleMessage(
		'peer',
		FF_WITNESS_FETCH_TYPE,
		encodeWitnessFetch(crypto.randomBytes(16), p.mailboxId, nonce, p.fetchPriv)
	);
	const reply = h.sent[before];
	expect(reply.type).to.equal(FF_WITNESS_FETCH_RESP_TYPE);
	return decodeWitnessFetchResp(reply.payload);
}

describe('FFOR witness store and service (Appendix F.5, section 9.6.4)', function () {
	this.timeout(20_000);
	const files: string[] = [];
	after(() => {
		for (const f of files) fs.rmSync(f, { force: true });
	});
	function tmpDb(): string {
		const f = path.join(
			os.tmpdir(),
			`ffor-witness-${crypto.randomBytes(4).toString('hex')}.db`
		);
		files.push(f);
		return f;
	}

	it('a mailbox survives a restart with R offline, and a nonce accepted before it is refused after it', () => {
		const file = tmpDb();
		const storage1 = new SqliteStorage(file);
		storage1.open();
		const h1 = serviceOn(ledgerOn(storage1));
		const { book: b, entries } = book(3);
		const p = provisionFor(b);
		const ack = provision(h1, p);
		expect(ack.ok, ack.error).to.be.true;
		expect(ack.witnessNodeId!.equals(W_ID)).to.be.true;
		expect(ack.retentionUntil).to.equal(800_200);
		expect(h1.events.map((e) => e.event)).to.include(
			'ffor:witness-provisioned'
		);
		// Idempotent: the same bytes again are the same ack.
		expect(provision(h1, p).ok).to.be.true;
		const nonce = crypto.randomBytes(32);
		const first = fetch(h1, p, nonce);
		expect(first.ok).to.be.true;
		expect(first.records).to.have.length(0);
		storage1.close();

		// The witness restarts: a fresh process over the same file, R offline.
		const storage2 = new SqliteStorage(file);
		storage2.open();
		const ledger2 = ledgerOn(storage2);
		const mailbox = ledger2.mailbox(p.mailboxId.toString('hex'));
		expect(mailbox, 'mailbox rehydrated').to.exist;
		expect(mailbox!.state).to.equal('PROVISIONED');
		expect(mailbox!.entries).to.have.length(3);
		// The hash index is rebuilt from the rows.
		const hit = ledger2.byHash(entries[1].paymentHash.toString('hex'));
		expect(hit?.k).to.equal(2);
		const h2 = serviceOn(ledger2);
		// The nonce the previous process accepted is still spent.
		const replay = fetch(h2, p, nonce);
		expect(replay.ok).to.be.true;
		expect(
			replay.records,
			'a replayed nonce answers like an empty mailbox'
		).to.have.length(0);
		const fresh = fetch(h2, p);
		expect(fresh.ok).to.be.true;
		storage2.close();
	});

	it('refuses a bad fetch_key signature, an inconsistent book, a short retention and receipts it cannot give', () => {
		const storage = new SqliteStorage(':memory:');
		storage.open();
		const h = serviceOn(ledgerOn(storage));
		const { book: good } = book(2);
		const refusal = (p: IProvision): string => {
			const ack = provision(h, p);
			expect(ack.ok).to.be.false;
			return ack.error ?? '';
		};
		// Signed by a key that is not the manifest's fetch_pubkey.
		const forged = provisionFor(good, {
			fetchPubkey: getPublicKey(crypto.randomBytes(32))
		});
		expect(refusal(forged)).to.match(/signature/);
		// H_act that the book does not reproduce.
		expect(
			refusal(provisionFor(good, { hAct: crypto.randomBytes(32) }))
		).to.match(/activation hash/);
		// A book whose slots repeat a hash.
		const dup = book(2);
		dup.entries[1].paymentHash = dup.entries[0].paymentHash;
		const dupBook = buildVoucherBook(
			sha256(Buffer.from('dup')),
			FforVariant.D,
			dup.entries
		);
		expect(refusal(provisionFor(dupBook))).to.match(/repeats a hash/);
		// A book whose slots are out of order.
		const swapped = book(2);
		[swapped.entries[0].k, swapped.entries[1].k] = [2, 1];
		expect(
			refusal(
				provisionFor(
					buildVoucherBook(
						sha256(Buffer.from('sw')),
						FforVariant.D,
						swapped.entries
					)
				)
			)
		).to.match(/1\.\.K/);
		// Retention under T_exp + 144.
		expect(refusal(provisionFor(good, { retentionUntil: 800_100 }))).to.match(
			/retention/
		);
		// Guardian receipts this witness does not offer.
		expect(refusal(provisionFor(good, { minReceipts: 1 }))).to.match(
			/receipts/
		);
		// Nothing was stored by any refusal.
		expect(h.service.listMailboxes()).to.have.length(0);
		// The good one lands, and its hashes may not be provisioned twice.
		expect(provision(h, provisionFor(good)).ok).to.be.true;
		expect(refusal(provisionFor(good))).to.match(/already held/);
		storage.close();
	});

	it('judges capacity against what it holds, and an unknown mailbox answers like an empty one', () => {
		const storage = new SqliteStorage(':memory:');
		storage.open();
		const h = serviceOn(ledgerOn(storage), { maxMailboxes: 2 });
		expect(provision(h, provisionFor(book(1, 'a').book)).ok).to.be.true;
		expect(provision(h, provisionFor(book(1, 'b').book)).ok).to.be.true;
		const third = provision(h, provisionFor(book(1, 'c').book));
		expect(third.ok).to.be.false;
		expect(third.error).to.match(/cannot reserve/);
		const small = new SqliteStorage(':memory:');
		small.open();
		const bytesBound = serviceOn(ledgerOn(small), { maxBytes: 1024 });
		// A 2-slot book reserves 2048 bytes: over the cap.
		expect(
			provision(bytesBound, provisionFor(book(2, 'd').book)).error
		).to.match(/cannot reserve/);
		small.close();
		// Probing: a mailbox nobody provisioned answers exactly like an empty one.
		const ghost = {
			wire: Buffer.alloc(0),
			mailboxId: crypto.randomBytes(32),
			fetchPriv: crypto.randomBytes(32)
		};
		const resp = fetch(h, ghost);
		expect(resp.ok).to.be.true;
		expect(resp.records).to.have.length(0);
		storage.close();
	});

	it('expires a mailbox past retention_until and releases its reservation', () => {
		const storage = new SqliteStorage(':memory:');
		storage.open();
		const ledger = ledgerOn(storage);
		const h = serviceOn(ledger, { maxMailboxes: 1 });
		const p = provisionFor(book(1, 'e').book);
		expect(provision(h, p).ok).to.be.true;
		expect(provision(h, provisionFor(book(1, 'f').book)).ok).to.be.false;
		h.service.onBlock(800_200);
		expect(ledger.mailbox(p.mailboxId.toString('hex'))!.state).to.equal(
			'PROVISIONED'
		);
		h.service.onBlock(800_201);
		expect(ledger.mailbox(p.mailboxId.toString('hex'))!.state).to.equal(
			'EXPIRED'
		);
		expect(h.events.map((e) => e.event)).to.include('ffor:witness-expired');
		expect(
			provision(h, provisionFor(book(1, 'f').book)).ok,
			'the slot is free again'
		).to.be.true;
		storage.close();
	});
});
