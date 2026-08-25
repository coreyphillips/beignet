/**
 * option_simple_close decode conformance against REAL eclair wire bytes.
 *
 * No upstream lightning/bolts test vectors exist for closing_complete /
 * closing_sig, so the fixture (vectors/eclair-simple-close.json) freezes
 * payloads captured from a live eclair 0.13 node by a
 * CAPTURE_VECTORS=1 run of tests/lightning/interop/eclair-simple-close.test.ts.
 * The fixture is a frozen reference: an ordinary interop run does not rewrite
 * it, so a decode regression against those real payloads fails here rather
 * than being re-frozen away. Skips cleanly if the fixture is missing, but a
 * fixture that is present and incomplete (one of the two message types gone)
 * is a failure, not a skip.
 */

import { expect } from 'chai';
import fs from 'fs';
import path from 'path';
import {
	decodeClosingCompleteMessage,
	decodeClosingSigMessage,
	encodeClosingCompleteMessage,
	encodeClosingSigMessage
} from '../../../src/lightning/message/channel-close';
import { MessageType } from '../../../src/lightning/message/types';

const FIXTURE = path.join(__dirname, 'vectors', 'eclair-simple-close.json');

interface IFixture {
	description: string;
	messages: Array<{ type: number; direction: string; payloadHex: string }>;
}

describe('Conformance: option_simple_close (eclair wire bytes)', function () {
	let fixture: IFixture | null = null;

	before(function () {
		if (!fs.existsSync(FIXTURE)) {
			console.log(
				'    ⚠ eclair-simple-close.json not captured yet — run the eclair interop test with CAPTURE_VECTORS=1 first'
			);
			this.skip();
			return;
		}
		fixture = JSON.parse(fs.readFileSync(FIXTURE, 'utf8'));
	});

	// A capture run replaces the fixture wholesale, so a partial capture would
	// quietly drop a whole message type while every remaining entry still
	// decodes. Both types are load-bearing coverage; require them explicitly.
	it('covers both closing_complete and closing_sig', function () {
		for (const type of [
			MessageType.CLOSING_COMPLETE,
			MessageType.CLOSING_SIG
		]) {
			expect(
				fixture!.messages.some((m) => m.type === type),
				`fixture carries a type ${type} message`
			).to.equal(true);
		}
	});

	it('decodes every captured message and re-encodes byte-identically', function () {
		expect(fixture!.messages.length).to.be.greaterThan(0);
		for (const m of fixture!.messages) {
			expect(
				m.type === MessageType.CLOSING_COMPLETE ||
					m.type === MessageType.CLOSING_SIG,
				`unexpected message type ${m.type} in fixture`
			).to.equal(true);
			const payload = Buffer.from(m.payloadHex, 'hex');
			const decoded =
				m.type === MessageType.CLOSING_COMPLETE
					? decodeClosingCompleteMessage(payload)
					: decodeClosingSigMessage(payload);

			expect(decoded.channelId.length).to.equal(32);
			expect(decoded.closerScriptPubkey.length).to.be.greaterThan(0);
			expect(decoded.feeSatoshis > 0n).to.equal(true);
			const sigs = [
				decoded.closerOutputOnlySig,
				decoded.closeeOutputOnlySig,
				decoded.closerAndCloseeSig
			].filter(Boolean) as Buffer[];
			expect(sigs.length).to.be.greaterThan(0);
			for (const sig of sigs) {
				expect(sig.length).to.equal(64);
			}
			if (m.type === MessageType.CLOSING_SIG) {
				expect(sigs.length, 'closing_sig carries exactly one sig').to.equal(1);
			}

			const reencoded =
				m.type === MessageType.CLOSING_COMPLETE
					? encodeClosingCompleteMessage(decoded)
					: encodeClosingSigMessage(decoded);
			expect(reencoded.equals(payload), 'byte-identical re-encode').to.equal(
				true
			);
		}
	});
});
