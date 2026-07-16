/**
 * Regression (S-B.M3): getByteCount priced a taproot key-path input at 138 vB
 * (552 WU) instead of ~57.5 vB, a ~2.4x fee overpay on every taproot spend (and
 * sendMax paid the recipient correspondingly less). It also missed the segwit
 * witness marker for P2TR, whose type name has no "W".
 */

import { expect } from 'chai';
import { getByteCount } from '../src/utils/transaction';

describe('getByteCount taproot pricing (S-B.M3)', () => {
	it('prices a taproot key-path input below a P2WPKH input', () => {
		// minByteCount 0 so the 166-byte floor does not mask the values.
		const p2tr = getByteCount({ P2TR: 1 }, { P2WPKH: 1 }, undefined, 0);
		const p2wpkh = getByteCount({ P2WPKH: 1 }, { P2WPKH: 1 }, undefined, 0);

		// A taproot key-path spend (~57.5 vB) is smaller than a P2WPKH spend
		// (~68 vB); before the fix P2TR was 138 vB, i.e. LARGER than P2WPKH.
		expect(p2tr).to.be.lessThan(p2wpkh);

		// Concrete size: 230 WU input + 2 WU segwit marker + 124 WU P2WPKH output
		// + 40 WU base/counts = 396 WU -> 99 vB.
		expect(p2tr).to.equal(99);
	});

	it('flags a taproot-only tx as segwit (witness marker counted)', () => {
		// P2TR has no "W" in its name; the input must still set hasWitness.
		const withMarker = getByteCount({ P2TR: 1 }, { P2TR: 1 }, undefined, 0);
		expect(withMarker).to.equal(
			Math.ceil((66 + 41 * 4 + 2 + 43 * 4 + 8 * 4 + 4 + 4) / 4)
		);
	});
});
