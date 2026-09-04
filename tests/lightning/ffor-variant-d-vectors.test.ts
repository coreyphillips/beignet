/**
 * FFOR Appendix D (specs/ffor-variant-d-vectors.md): the Variant D setup
 * transcript, byte for byte.
 *
 * The fixture constants below are copied from the generator
 * (specs/tools/generate-ffor-variant-d-vectors.ts) and the expected values
 * from the appendix. Every signed message, every section 7.5.2 hash, both
 * commitment views and the voucher onion are rebuilt here with the ffor
 * module's codecs and beignet's own builder, and compared to the appendix.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	buildLocalCommitment,
	buildRemoteCommitment,
	signRemoteCommitment,
	verifyRemoteCommitmentSig,
	verifyRemoteHtlcSignatures
} from '../../src/lightning/channel/commitment-builder';
import {
	createOpenerState,
	createAcceptorState,
	IChannelState
} from '../../src/lightning/channel/channel-state';
import {
	ChannelState,
	HtlcDirection,
	HtlcState,
	IChannelConfig
} from '../../src/lightning/channel/types';
import { deriveChannelId } from '../../src/lightning/channel/validation';
import {
	IChannelBasepoints,
	perCommitmentPointFromSecret
} from '../../src/lightning/keys/derivation';
import { ChannelSigner } from '../../src/lightning/keys/signer';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';
import {
	constructOnionPacket,
	encodeOnionPacket,
	decodeOnionPacket,
	processOnionPacket,
	isFinalHop
} from '../../src/lightning/onion';
import { Feature, FeatureFlags } from '../../src/lightning/features/flags';
import {
	FF_ACCEPT_TYPE,
	FF_ACTIVATE_ACK_TYPE,
	FF_ACTIVATE_TYPE,
	FF_INIT_TYPE,
	FforVariant,
	IFforBookEntry
} from '../../src/lightning/ffor/types';
import {
	decodeFforAcceptMessage,
	decodeFforActivateAckMessage,
	decodeFforActivateMessage,
	decodeFforInitMessage,
	encodeFforAcceptUnsigned,
	encodeFforActivateAckUnsigned,
	encodeFforActivateUnsigned,
	encodeFforInitUnsigned,
	fforWireBytes,
	signFforMessage,
	verifyFforMessage
} from '../../src/lightning/ffor/messages';
import {
	buildVoucherBook,
	computeHAct,
	computeHBook,
	computeHCommit,
	computeTInit,
	computeTSetup,
	voucherPaymentSecret
} from '../../src/lightning/ffor/transcript';
import {
	checkVoucherBook,
	feeS,
	grossIntoS
} from '../../src/lightning/ffor/amounts';
import { buildVoucherOnion } from '../../src/lightning/ffor/voucher';

function sha256(b: Buffer): Buffer {
	return crypto.createHash('sha256').update(b).digest();
}
function h2b(s: string): Buffer {
	return Buffer.from(s, 'hex');
}
function ascii(s: string): Buffer {
	return Buffer.from(s, 'ascii');
}
function u16(v: number): Buffer {
	const b = Buffer.alloc(2);
	b.writeUInt16BE(v);
	return b;
}
function pcSecret(seed: Buffer, n: bigint): Buffer {
	return generateFromSeed(seed, MAX_INDEX - n);
}
function pcPoint(seed: Buffer, n: bigint): Buffer {
	return perCommitmentPointFromSecret(pcSecret(seed, n));
}

// ---- D.0 shared fixture ---------------------------------------------------

const R_FUNDING_PRIV = h2b(
	'30ff4956bbdd3222d44cc5e8a1261dab1e07957bdac5ae88fe3261ef321f3749'
);
const S_FUNDING_PRIV = h2b(
	'1552dfba4f6cf29a62a0af13c8d6981d36d0ef8d61ba10fb0fe90da7634d7e13'
);
const R_PAYMENT_BASEPOINT_SECRET = h2b('11'.repeat(32));
const S_REVOCATION_BASEPOINT_SECRET = h2b('22'.repeat(32));
const R_DELAYED_BASEPOINT_SECRET = h2b('33'.repeat(32));
const S_PAYMENT_BASEPOINT_SECRET = h2b('44'.repeat(32));
const R_REVOCATION_BASEPOINT_SECRET = sha256(
	ascii('ffor/R/revocation-basepoint-secret')
);
const S_DELAYED_BASEPOINT_SECRET = sha256(
	ascii('ffor/S/delayed-payment-basepoint-secret')
);
const R_PC_SEED = sha256(ascii('ffor/R/per-commitment-seed'));
const S_PC_SEED = sha256(ascii('ffor/S/per-commitment-seed'));
const R_NODE_PRIV = sha256(ascii('ffor/R/node-key'));
const S_NODE_PRIV = sha256(ascii('ffor/S/node-key'));
const R_NODE_PUB = getPublicKey(R_NODE_PRIV);
const S_NODE_PUB = getPublicKey(S_NODE_PRIV);

const FUNDING_TXID_INTERNAL =
	'bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489';
const FUNDING_SAT = 10_000_000n;
const FEERATE_PER_KW = 2500;
const DUST_LIMIT_SAT = 546n;
const TO_SELF_DELAY = 144;
const CHANNEL_RESERVE_SAT = 10_000n;
const MAX_ACCEPTED_HTLCS = 483;
const MAX_HTLC_VALUE_IN_FLIGHT_MSAT = 5_000_000_000n;
const HTLC_MINIMUM_MSAT = 1n;
const N_R = 42n;
const N0 = 42n;
const T_EXP = 800_000;
const D_DEADLINE = 798_992;
const EPOCH_START_HEIGHT = 790_000;
const FEE_BASE_MSAT = 1000;
const FEE_PROP_MILLIONTHS = 5000;
const MIN_PAYMENT_MSAT = 546_000n;
const S_BALANCE_MSAT_PRE = 7_000_000_000n;
const R_BALANCE_MSAT_PRE = 3_000_000_000n;

const rBasepoints: IChannelBasepoints = {
	fundingPubkey: getPublicKey(R_FUNDING_PRIV),
	revocationBasepoint: getPublicKey(R_REVOCATION_BASEPOINT_SECRET),
	paymentBasepoint: getPublicKey(R_PAYMENT_BASEPOINT_SECRET),
	delayedPaymentBasepoint: getPublicKey(R_DELAYED_BASEPOINT_SECRET),
	htlcBasepoint: getPublicKey(R_PAYMENT_BASEPOINT_SECRET),
	firstPerCommitmentPoint: pcPoint(R_PC_SEED, 0n)
};
const sBasepoints: IChannelBasepoints = {
	fundingPubkey: getPublicKey(S_FUNDING_PRIV),
	revocationBasepoint: getPublicKey(S_REVOCATION_BASEPOINT_SECRET),
	paymentBasepoint: getPublicKey(S_PAYMENT_BASEPOINT_SECRET),
	delayedPaymentBasepoint: getPublicKey(S_DELAYED_BASEPOINT_SECRET),
	htlcBasepoint: getPublicKey(S_PAYMENT_BASEPOINT_SECRET),
	firstPerCommitmentPoint: pcPoint(S_PC_SEED, 0n)
};

const channelTypeFlags = FeatureFlags.empty();
channelTypeFlags.setCompulsory(Feature.STATIC_REMOTE_KEY);
channelTypeFlags.setCompulsory(Feature.ANCHOR_ZERO_FEE_HTLC);
const CHANNEL_TYPE = channelTypeFlags.toBuffer();

const CONFIG: IChannelConfig = {
	dustLimitSatoshis: DUST_LIMIT_SAT,
	maxHtlcValueInFlightMsat: MAX_HTLC_VALUE_IN_FLIGHT_MSAT,
	channelReserveSatoshis: CHANNEL_RESERVE_SAT,
	htlcMinimumMsat: HTLC_MINIMUM_MSAT,
	toSelfDelay: TO_SELF_DELAY,
	maxAcceptedHtlcs: MAX_ACCEPTED_HTLCS,
	feeratePerKw: FEERATE_PER_KW
};

const CHANNEL_ID = deriveChannelId(h2b(FUNDING_TXID_INTERNAL), 0);
const sSigner = new ChannelSigner(S_FUNDING_PRIV, S_PAYMENT_BASEPOINT_SECRET);
const rSigner = new ChannelSigner(R_FUNDING_PRIV, R_PAYMENT_BASEPOINT_SECRET);

type Funder = 'S' | 'R';

function makeStates(funder: Funder): {
	sState: IChannelState;
	rState: IChannelState;
} {
	let sState: IChannelState;
	let rState: IChannelState;
	if (funder === 'S') {
		sState = createOpenerState({
			temporaryChannelId: Buffer.alloc(32),
			fundingSatoshis: FUNDING_SAT,
			pushMsat: R_BALANCE_MSAT_PRE,
			localConfig: { ...CONFIG },
			localBasepoints: sBasepoints,
			localPerCommitmentSeed: S_PC_SEED
		});
		sState.remoteBasepoints = rBasepoints;
		sState.remoteConfig = { ...CONFIG };
		rState = createAcceptorState({
			temporaryChannelId: Buffer.alloc(32),
			fundingSatoshis: FUNDING_SAT,
			pushMsat: R_BALANCE_MSAT_PRE,
			localConfig: { ...CONFIG },
			localBasepoints: rBasepoints,
			localPerCommitmentSeed: R_PC_SEED,
			remoteBasepoints: sBasepoints,
			remoteConfig: { ...CONFIG }
		});
	} else {
		rState = createOpenerState({
			temporaryChannelId: Buffer.alloc(32),
			fundingSatoshis: FUNDING_SAT,
			pushMsat: S_BALANCE_MSAT_PRE,
			localConfig: { ...CONFIG },
			localBasepoints: rBasepoints,
			localPerCommitmentSeed: R_PC_SEED
		});
		rState.remoteBasepoints = sBasepoints;
		rState.remoteConfig = { ...CONFIG };
		sState = createAcceptorState({
			temporaryChannelId: Buffer.alloc(32),
			fundingSatoshis: FUNDING_SAT,
			pushMsat: S_BALANCE_MSAT_PRE,
			localConfig: { ...CONFIG },
			localBasepoints: sBasepoints,
			localPerCommitmentSeed: S_PC_SEED,
			remoteBasepoints: rBasepoints,
			remoteConfig: { ...CONFIG }
		});
	}
	for (const st of [sState, rState]) {
		st.channelId = CHANNEL_ID;
		st.fundingTxid = h2b(FUNDING_TXID_INTERNAL);
		st.fundingOutputIndex = 0;
		st.channelType = CHANNEL_TYPE;
		st.state = ChannelState.NORMAL;
	}
	sState.localCommitmentNumber = N0;
	sState.remoteCommitmentNumber = N_R;
	rState.localCommitmentNumber = N_R;
	rState.remoteCommitmentNumber = N0;
	return { sState, rState };
}

// ---- Expected values (Appendix D.1 to D.5) --------------------------------

interface IScenarioExpect {
	id: string;
	funder: Funder;
	amounts: bigint[];
	sHtlcIdBase: bigint;
	epochId: string;
	initSig: string;
	initWireSha256: string;
	tInit: string;
	acceptSig: string;
	acceptWireSha256: string;
	tSetup: string;
	hBook: string;
	rTxidInternal: string;
	sTxidInternal: string;
	rViewCommitSig: string;
	sViewCommitSig: string;
	hCommit: string;
	activateSig: string;
	activateWireSha256: string;
	hAct: string;
	ackSig: string;
	ackWireSha256: string;
}

const SCENARIOS: IScenarioExpect[] = [
	{
		id: 'D.1',
		funder: 'S',
		amounts: [1_000_000n],
		sHtlcIdBase: 0n,
		epochId: 'fc4bc36f402d396fe452db96030f1563fd554e9c9f9313ef4cdd6299d21dff15',
		initSig:
			'b650a5af1658bafe768dc0d5b07af4556ee5776b010bd4da19cd64aefd40f1a0184923774f95b2d3d9e024283db263075e8ed6f793ba4553b9960e638fd90933',
		initWireSha256:
			'a714370c47b0851d7c96e218db2673cb7c9eaa8cff435c80bb71efdbe131e62c',
		tInit: '343331edc28e500ea03cbce26983583e66fff33dc9f096a3d6924b8239f68eb8',
		acceptSig:
			'98fbd933af0a181f69b015f155a48608d1295327607d85bdb03a9598b54dc58f6ac01b0421309cebbbaa596e62113de7e6fe2aafaccc281f535eda535525b3ba',
		acceptWireSha256:
			'9d532e9b5d95331e0234481ea4db5546b34a4a80a275147dc865c9195beaeea8',
		tSetup: 'ba34be8afe89e4457543a6e7279f86054f1d6e9038234b786b740e9c905c001f',
		hBook: '8ae276dd460c7b2030287a608677bc51eb9cdef5b7cfc1f73d005e463076510a',
		rTxidInternal:
			'c56247558caf290d78e2fe7d948d9605320c012b20fa181db87fc847ce69159b',
		sTxidInternal:
			'd23aaf74371cdda6cbaf75b7390fdd75b3247dfe90c98d2e19e9802783c349b9',
		rViewCommitSig:
			'fc6f3e0643bb13df8e0a2b734c9276d22437b9fe32786b717a73c0cf055f8f7d3f3e4322082efe935e60e52564ec176a7504241db0dafd54bd8f8830b1823394',
		sViewCommitSig:
			'af1acf12557e3adb26d85dd9d22a5875de461214be9c02c1fdc5fcce986b33997e8c8c010cd40982b20e1658893700fce9afb784b396903ee321fc43a8f56823',
		hCommit: '723024696ad20b4758b228284620d18fd30750b7051cc64efca23a1417cf1321',
		activateSig:
			'03aa4c0c160338dfb3783120761fb4a6053836307e196fe3597032f28715b9a021074ec06ceb9c5f06af9854f8b21ff1b6b74ff3ae326a049de8270f2c8dc559',
		activateWireSha256:
			'bfcb0d72e13c21547d6b7c2f83120f82ab669ef5ed4c62c0d9682eb3ae6e964e',
		hAct: '580a4a958e8131b32452741e51d724e0f231cb518896c743fa59de236ac6e716',
		ackSig:
			'1a20d93b0e00046483cffe0d9b54b0747a351ccaa3971a92aaf9245eb7cde5734f20a6ed584ccd30d81e833d9e89d9d9e42878b541cce5913a647b5ffc1ca9a3',
		ackWireSha256:
			'42bb5550e44f03bb868f446201464fc3632d68faf9e54465e4dfe8811e493515'
	},
	{
		id: 'D.2',
		funder: 'S',
		amounts: [994_000n, 546_250n, 49_749_000n],
		sHtlcIdBase: 7n,
		epochId: '2436d73f6fdf469b68bedbbd9c90aa51871d491fadf862d815853b27f13f62d6',
		initSig:
			'1950e84703f6ab745d5e93ed17fadd4cb4750b1b4bc04b01b18dd4051b0fc58114f5b24aa52b2a1c5c391d98621ce6a37512049c6dac1cbf048f61cb52868547',
		initWireSha256:
			'b904e7944d94b3336287a3ebdb21222a70322eb227bbc35c3304bef81caa061c',
		tInit: '19644c62830070c3d7ca623b582f274e6e94669d4938e54262a1c6e6e6ed1791',
		acceptSig:
			'05ec065a191d90cbb8a6adbeb0d1fd2838be33fa511588e2a3ccb83ce7313a0a1946d43ead676cd1be4a6780b5dd6feb03dc71f0c8d98056ce61304ab243d91b',
		acceptWireSha256:
			'25a8b2da07d035a1c61c87b2219b222bac8233f6a2612f495140496a6eaf8ba5',
		tSetup: '8465b03bd1ab3001129cd91fffb6e5129460cf82fb396cad2ebbb0ede8916396',
		hBook: '09e4e3f8cef88225f7401bdcf539cf557932eeb035a265d602afba2083125eec',
		rTxidInternal:
			'2cc9f550a3c31100426d327e5308e0ee875b1c33d2382097027f0db822320b83',
		sTxidInternal:
			'69e73334f97a3fe4ddcde4f3161ba1112d6d5bc6953e95199f0ec0bb1b552e2c',
		rViewCommitSig:
			'92c278e36c901e20bf49bf1cb47c7edd3bfad7782a74f793eb005631211396801053673903571b61b39b3af5770202724434c5ed7aa360c7111d43a26623dc20',
		sViewCommitSig:
			'275cfb1344cd85ff0d0e6bbafc44f611c1723f2e35944ed58fd4bebe41b1f66d01fa9c47a071fcd480f77742d7a1cd0f158fd5d19ec3ef28c4673d540e2611de',
		hCommit: 'e7e996cb809a52736589d78d22b1a7c2a76b2ba07a8ac1f957aabc2651b0b9c5',
		activateSig:
			'1b5ca88c942d833703ab7702576abcbe1694524b37ef6b762f61358c9e2c31710cd2d600c69ef3a810d29a4b25705759de647e7b666909f0baec2a7af766eca4',
		activateWireSha256:
			'fac9ff2295db3814988ee47a572ee8ffea11ce185e22cf81addb304f2e4d7029',
		hAct: '1d561fb397d1ac599cf6876a4f390d6bd81de4cd425b30383b14a5de4b4b61d4',
		ackSig:
			'0e976c39f969145764a509691cd84aafedaddd873be2e3b35fbb42b55d43087b79aadcd67eb097ea539931314d7b8aee65758147094f78cd43736c0e496d2e66',
		ackWireSha256:
			'bcde669e38e05cb563ae9d043e6b4f3e5b7796605e958f3cb9928e63cb0feba6'
	},
	{
		id: 'D.3',
		funder: 'R',
		amounts: [994_000n, 546_250n, 49_749_000n],
		sHtlcIdBase: 0n,
		epochId: '8685960c118c83535c1bcc47e33666a775e26e9d1ca6cbca79aade33f9fe3ecb',
		initSig:
			'b1ab264efb4d47b962fe9f5aeb72b5c1d67e5f0cd7709835f07a6bd58450fa9a048758571653c17a8c91eacd8750cbc7efe0bd648caca5c1861ed14ccad2c885',
		initWireSha256:
			'a582ea67e64b6c52fc505c6fa356fcde75773c34424519258e36c8ceb9cf9100',
		tInit: '196ce823fe02a2daea0a6a544f05f7b1c51520c0c323836663b31af3318a9cf0',
		acceptSig:
			'25b2bb680e71adfd82af8c7ff8a10a871775112ca01901a0dc56895b5e1217567c4f5dada7a4da2f3e4211d7faf6db8664f59d1062d31b31ba83d4233462b07d',
		acceptWireSha256:
			'c53ba231be91339dcc271b289bf7f8627fcb4512a867decb4c1a38fce23772da',
		tSetup: '43bce577aa29c966a8c9a8bc614a9edfc4994f8ee4954414bc635cb6dcd745ff',
		hBook: '5bb093a59800241c8f94a2ab083fadadda85a5d08e81b046e0dcf4623310819b',
		rTxidInternal:
			'a351e3b1b081a909e61b6106a8c4684aebbb40c32f597aa2d2a0494eea7468c6',
		sTxidInternal:
			'37f499ed459db4049a86c452b91740a254f550f678a0e85b6bbf063b1dbedada',
		rViewCommitSig:
			'b57ef954b02973379279ff14c16999fd3914199dfd058be0bef2850a26de895e2361355c3f7ca067c613c62c78200e6200d26e3b174d824ba2e9840bd9a98c26',
		sViewCommitSig:
			'1036b69c5c0e4097cd81d903763ffffda4d928f3d2bdf86adfaeeba732055c1e58356fa89e01b6e69bee7c36cac774db9b531c40fd69cb853b3cee9bf8d0de45',
		hCommit: 'c034dadab45e153536220113ba43e4aeaf2a87391cda1fa33b9d7d89472ce5ad',
		activateSig:
			'872c5320024fbba9ee9ee119fc2b61b48107ee6aed280b508eae7d233e8bc9db501f0541eb37c0649ef9526e75f035d355a6dede257c86d1222a728814cd8d82',
		activateWireSha256:
			'0cafc03c292dbd12713817ae30f9009913411949e5a7a114bd43abe1fab3ba90',
		hAct: 'bcb6c726241e7b35d19c5e0f952271531cf2e61b4979c61cf8c817ebcd22da03',
		ackSig:
			'b07d07776548693e5a9ceace1cca137794ef60f13c53d67ad6ac4baa64518e8576fa49931dd22c60ccd8b66d1319834cb6993d41df0b281dd45930f1b5e475b4',
		ackWireSha256:
			'863db3513a0a676edc69c216245e8f4c34b0a319866b283138f2cfb157604071'
	},
	{
		id: 'D.4',
		funder: 'S',
		amounts: [546_000n],
		sHtlcIdBase: 0n,
		epochId: '87cb2b4c1f4e6b9246bc30f7a7cb145dff0ad8b75153061fe08a31344ec15a0d',
		initSig:
			'babbf4d69c60af8d49aaca2364c217375b270927d0340b18f630396bb6d9b1cd5490997cf98fc8ea3d38ef2f517e3a6e26e0ec9ce8c33ae503625e40a46fa451',
		initWireSha256:
			'fefb08c339f5bbac4c7f3ab6a0e3b8f62d1a7f254f7131a02edf420a5d26764b',
		tInit: 'b4a90a0eb194b5d7d283a45707f5778bfca2eda67c762e3f548520024f0cc257',
		acceptSig:
			'5f178313b04c050db7aa8053d8fd271677247d8058ac49f3096d0f7abc1d09f75c82c95bcb0702117007a7ca143b106392a006f81cde971644bdad587af2cc7f',
		acceptWireSha256:
			'b28ba7c903c3e74dbab51727ef6fa9624723896166f338d4d0ab59c8198465bd',
		tSetup: '29b3ef77eec90177a34bf4d9785afd1fd6ffb2a28bad4ed571f295fe711c35a9',
		hBook: '6beceabe7c2571353e03fdb7f82e3f4241c2467967ba67c2b9efebf32a4a6839',
		rTxidInternal:
			'6c5524cdfb79105aa2431263458cc44849c91f1af2218c5bede450935b40b8e3',
		sTxidInternal:
			'6fd405cb69cf32914b5de6c56cf73a034c29a1b8472edf5ef6a4d840535ed995',
		rViewCommitSig:
			'8e420eb09afc9e14917d109289aba738be760222ab59f798568b741e81eeaa394d371ecda81fb17a8019d2173c81eaca0341d7efa7c03662c32b58e63c725a25',
		sViewCommitSig:
			'2335308ef0bef56849b2dc5b708f1bb4b68fa14f33601ccbdfc4fcac5a89238a5e740090457fd412a7f5041d94985bbfb12c36e8b9461e8f69924d65e22e47ee',
		hCommit: '06602b655a1dbeb1059e87e9f8c0fefd89bed2a6501a5df25724e54d1c2e56fe',
		activateSig:
			'2938ff94475f468d79e2503c5159adc276699ea1681343cf53169b350b3046ae09015bb2005c24c4f8d9f19649523ed164abbe7f367ff2687cf8a27ebacfff91',
		activateWireSha256:
			'921d58873ec272c8784c5efebdfe4534dd9a72c5053842189ac7afd136046c43',
		hAct: '982ee14fdd19b21558b89adda15b53f54122fc1c5a72bae5ef4261ee154cc776',
		ackSig:
			'e551b9a3347022ed74ca206fe49684de31f1150e6d3aace73807bf6055b24942176c45fb7eb36a13f2c1e3866e223cef4617b6740621c114f7278f68d283d000',
		ackWireSha256:
			'52754e709395539b366ca52ad8c326baa7c0707a825f37d319ea9b28198bf8a4'
	},
	{
		id: 'D.5',
		funder: 'S',
		amounts: Array.from({ length: 483 }, () => 546_000n),
		sHtlcIdBase: 0n,
		epochId: '57d51e11b3a8feac73e8ea58aa6824b7bba69e045416f6ba4a586348adc40da6',
		initSig:
			'17a3e152d4dca7cfe072f02634463aa789ac5e5a0c4dbaed0ce8cb7baf418ffa25f7b1a4f8d10e36916250b3cb6098ca4fb177335d1c24c78ed9e69cc3939805',
		initWireSha256:
			'5158dc207f210dacb4756e8d31a3b8a20f95130cfe085fa7b52cbd637b43888b',
		tInit: 'e0c80af58e7643d04abbd00763600d69e7ad33429020676adae4d4d341201b3e',
		acceptSig:
			'8f809b84eb46a8e2f6891931ceb07e375c8f7df92beae625f3a2193c77a1f5da52bf64dd15d0231dbb13c5594a519c0eaee2ed23ff4d269a9919b204c3aae789',
		acceptWireSha256:
			'5b9d7c2c17530f1d0821a7d53f1f6358f04b785b73cfd6516c8e0f546a4420c2',
		tSetup: 'e012e565964e65d584adbc7138f1d115f6e00c27a90903e6c1b1657982fe5cff',
		hBook: '556ddfc432a327526e84bbfe843070d8fca46b05d25b3a0dfccd406ec4f03a29',
		rTxidInternal:
			'31d842bb6d8a1529dd54d013c7a439827864c4ff4867a8af5080a68b0f25aed4',
		sTxidInternal:
			'b772ab617557851d0f05d96026f51ff9b7baf43c6ef3ee72153495c41c8c2b09',
		rViewCommitSig:
			'5199301fd2ed3e50f93eb4b0153cd7171ae77dc92797ab8baf9b166c08c1e792300d9fb8731445631dbe96052aa4cd3676850aeb557ed09e332cf0e9874f3ea6',
		sViewCommitSig:
			'f9cc1eda139168d6ca5c1af69dccd5c1084f16d42db38e2e10691020bc3966f54a947ba26392abddf76d9aaae5be042fc87c78fdb28b92d2f63a28001fdeaddb',
		hCommit: '61034010d3510c0a44a53e0ef4a086226bfa039708f944ce4da9833f1ad5e5f3',
		activateSig:
			'5779c6f246b9d57721a604df34edb76ca1669844ee5799dc2eadacb6ba6d531254e954c09d705cdf51e5ea9728528cccc4af0bdebe4dd29853e8315e96edca63',
		activateWireSha256:
			'f1a2399dc4a9a9bc31a5323c6edd1043710d4fd54e297cbf8126b680166e9afb',
		hAct: '7d36f8f1728a75368594fed88f57f4b24113c1a76d673264b1a2b89c4a233365',
		ackSig:
			'8196bbac6ca9362246f559f4c15d5645ef908635dc460bdaea0f3e8e860460215c584b017c77a3a2254a39d5832206367aa74cd262def4e8a819c60a2360b988',
		ackWireSha256:
			'b399a87525eb3634d1fd283109542ac8f9c8bbdf5b4c074671bd7f514bbc5489'
	}
];

/** D.1's complete messages, for a whole-wire comparison. */
const D1_INIT_WIRE =
	'd6d9bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489fc4bc36f402d396fe452db96030f1563fd554e9c9f9313ef4cdd6299d21dff150400000000000f4240000100000000000854d0000c3110000c3500000003e80000138800000000000000000000090800000000000f4240b650a5af1658bafe768dc0d5b07af4556ee5776b010bd4da19cd64aefd40f1a0184923774f95b2d3d9e024283db263075e8ed6f793ba4553b9960e638fd90933';
const D1_ACCEPT_WIRE =
	'd6dbbef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489fc4bc36f402d396fe452db96030f1563fd554e9c9f9313ef4cdd6299d21dff15000000000000002a0120a0a62adc5092cd3c202aaea0900b5826c242194c5f9984070e833e58b273eda507080000000000000000090800000000000f42400b20343331edc28e500ea03cbce26983583e66fff33dc9f096a3d6924b8239f68eb898fbd933af0a181f69b015f155a48608d1295327607d85bdb03a9598b54dc58f6ac01b0421309cebbbaa596e62113de7e6fe2aafaccc281f535eda535525b3ba';
const D1_ACTIVATE_WIRE =
	'd705bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489fc4bc36f402d396fe452db96030f1563fd554e9c9f9313ef4cdd6299d21dff15ba34be8afe89e4457543a6e7279f86054f1d6e9038234b786b740e9c905c001f8ae276dd460c7b2030287a608677bc51eb9cdef5b7cfc1f73d005e463076510a723024696ad20b4758b228284620d18fd30750b7051cc64efca23a1417cf1321000c0df003aa4c0c160338dfb3783120761fb4a6053836307e196fe3597032f28715b9a021074ec06ceb9c5f06af9854f8b21ff1b6b74ff3ae326a049de8270f2c8dc559';
const D1_ACK_WIRE =
	'd707bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489fc4bc36f402d396fe452db96030f1563fd554e9c9f9313ef4cdd6299d21dff15580a4a958e8131b32452741e51d724e0f231cb518896c743fa59de236ac6e7161a20d93b0e00046483cffe0d9b54b0747a351ccaa3971a92aaf9245eb7cde5734f20a6ed584ccd30d81e833d9e89d9d9e42878b541cce5913a647b5ffc1ca9a3';
const D1_BOOK =
	'fc4bc36f402d396fe452db96030f1563fd554e9c9f9313ef4cdd6299d21dff15040100010001a0a62adc5092cd3c202aaea0900b5826c242194c5f9984070e833e58b273eda500000000000f4240000c3500000c31100000000000000000';
const D1_VOUCHER1_HASH =
	'a0a62adc5092cd3c202aaea0900b5826c242194c5f9984070e833e58b273eda5';
const D1_VOUCHER1_PREIMAGE =
	'8ae4a313bd01bcfcce12b797ed20603ed56b0f0b9194e7c000e5cbd6fe376517';
const D1_VOUCHER1_SECRET =
	'8b85975abbc66f6c888e98520b2483c9dd7db4a6bde4365784e31a99f741bf26';
const D1_VOUCHER1_SESSION =
	'4315bab9f33eed8ecc8a810d5516c248ab5d6dffc429a7371fd334c692149fe3';
const D1_VOUCHER1_EPHEMERAL =
	'02344218e0161cb82979280a8b155b93a7c901b409e987d9ca893bd025fb9774a3';
const D1_ADD_HTLC_PREFIX =
	'0080bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000000000000000000000f4240a0a62adc5092cd3c202aaea0900b5826c242194c5f9984070e833e58b273eda5000c3500';
const D1_R_VIEW_TX =
	'0200000001bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000070c5b980054a010000000000002200202b1b5854183c12d3316565972c4668929d314d81c5dcdbb21cb45fe8a9a8114f4a01000000000000220020e9e86e4823faa62e222ebc858a226636856158f07e69898da3b0d1af0ddb3994e80300000000000022002096ff0fd0d009591a4143b5eba0d8e49bda7268238219ea2899b090a9ac6f51bbc0c62d00000000002200202dc58b936232a6526119fc481e6314ae008c7041fae49223ba9aecba4916ce479cbc6a0000000000220020f3394e1e619b0eca1f91be2fb5ab4dfc59ba5b84ebe014ad1d43a564d012994a8281f020';
const D1_S_VIEW_TX =
	'0200000001bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000070c5b980054a010000000000002200202b1b5854183c12d3316565972c4668929d314d81c5dcdbb21cb45fe8a9a8114f4a01000000000000220020e9e86e4823faa62e222ebc858a226636856158f07e69898da3b0d1af0ddb3994e803000000000000220020fde971d119e6f42f577ea2127ce99c100628d8cc6ba707ddbd297af84e61649ec0c62d000000000022002032e8da66b7054d40832c6a7a66df79d8d7bcccd5ffa53f5dd1772cb9cb9f32839cbc6a0000000000220020ffc926acab2a33451aa40abb548de617d2c7fb93751971cfea75fcd5e11db6868281f020';
const D1_R_VIEW_HTLC_SIG =
	'f7bd287775c2dd7ca95aba29bcb15a2d627394c9261687ae010d5211229c6d122a8646bb730048ecd1964ba0c985a78a939d9ea51721193ccfa078cb322f88e5';
const D1_S_VIEW_HTLC_SIG =
	'3a4626510473d943fbfac72d7038a903d2f343b1242928904d8dcd0cda6893ee7dfd6588fe52877c6036d72892403ec764bc0de0a495b64da69d2e70e7d322f3';

interface IBuilt {
	epochId: Buffer;
	hashes: Buffer[];
	preimages: Buffer[];
	initBody: Buffer;
	initWire: Buffer;
	tInit: Buffer;
	acceptBody: Buffer;
	acceptWire: Buffer;
	tSetup: Buffer;
	book: Buffer;
	hBook: Buffer;
	rView: {
		txHex: string;
		txidInternal: Buffer;
		sig: Buffer;
		htlcSigs: Buffer[];
	};
	sView: {
		txHex: string;
		txidInternal: Buffer;
		sig: Buffer;
		htlcSigs: Buffer[];
	};
	hCommit: Buffer;
	activateBody: Buffer;
	activateWire: Buffer;
	hAct: Buffer;
	ackBody: Buffer;
	ackWire: Buffer;
}

function buildScenario(sc: IScenarioExpect): IBuilt {
	const K = sc.amounts.length;
	const budget = sc.amounts.reduce((a, b) => a + b, 0n);
	const epochId = sha256(ascii(`ffor/vector/${sc.id}/epoch_id`));
	const preimages = sc.amounts.map((_, i) =>
		sha256(Buffer.concat([ascii(`ffor/vector/${sc.id}/preimage`), u16(i + 1)]))
	);
	const hashes = preimages.map((p) => sha256(p));

	const initBody = signFforMessage(
		FF_INIT_TYPE,
		encodeFforInitUnsigned({
			channelId: CHANNEL_ID,
			epochId,
			variant: FforVariant.D,
			budgetMsat: budget,
			maxPayments: K,
			minPaymentMsat: MIN_PAYMENT_MSAT,
			settlementDeadline: D_DEADLINE,
			voucherExpiry: T_EXP,
			feeBaseMsat: FEE_BASE_MSAT,
			feeProportionalMillionths: FEE_PROP_MILLIONTHS,
			escapeGranularityMsat: 0n,
			rPerCommitmentPoints: [],
			voucherAmountsMsat: sc.amounts
		}),
		R_NODE_PRIV
	);
	const initWire = fforWireBytes(FF_INIT_TYPE, initBody);
	const tInit = computeTInit(initWire);

	const acceptBody = signFforMessage(
		FF_ACCEPT_TYPE,
		encodeFforAcceptUnsigned({
			channelId: CHANNEL_ID,
			epochId,
			sCommitmentNumber: N0,
			paymentHashes: hashes,
			sHtlcIdBase: sc.sHtlcIdBase,
			voucherAmountsMsat: sc.amounts,
			initHash: tInit
		}),
		S_NODE_PRIV
	);
	const acceptWire = fforWireBytes(FF_ACCEPT_TYPE, acceptBody);
	const tSetup = computeTSetup(tInit, acceptWire);

	const entries: IFforBookEntry[] = sc.amounts.map((d, i) => ({
		k: i + 1,
		paymentHash: hashes[i],
		amountMsat: d,
		voucherExpiry: T_EXP,
		settlementDeadline: D_DEADLINE,
		sHtlcId: sc.sHtlcIdBase + BigInt(i)
	}));
	const book = buildVoucherBook(epochId, FforVariant.D, entries);
	const hBook = computeHBook(book);

	const { sState, rState } = makeStates(sc.funder);
	for (let i = 0; i < K; i++) {
		const base = {
			id: sc.sHtlcIdBase + BigInt(i),
			amountMsat: sc.amounts[i],
			paymentHash: hashes[i],
			cltvExpiry: T_EXP,
			onionRoutingPacket: Buffer.alloc(1366),
			state: HtlcState.COMMITTED
		};
		sState.htlcs.set(`v${i}`, { ...base, direction: HtlcDirection.OFFERED });
		rState.htlcs.set(`v${i}`, { ...base, direction: HtlcDirection.RECEIVED });
		sState.localBalanceMsat -= sc.amounts[i];
		rState.remoteBalanceMsat -= sc.amounts[i];
	}
	const rPoint = pcPoint(R_PC_SEED, N_R + 1n);
	const sPoint = pcPoint(S_PC_SEED, N0 + 1n);

	const view = (
		builder: IChannelState,
		holder: IChannelState,
		builderSigner: ChannelSigner,
		holderSigner: ChannelSigner,
		point: Buffer,
		n: bigint
	): IBuilt['rView'] => {
		const built = buildRemoteCommitment(builder, point, n);
		const { signature, htlcSignatures } = signRemoteCommitment(
			builder,
			builderSigner,
			point,
			n
		);
		const rebuilt = buildLocalCommitment(holder, point, n);
		expect(rebuilt.result.tx.toHex()).to.equal(built.result.tx.toHex());
		expect(verifyRemoteCommitmentSig(holder, holderSigner, point, signature, n))
			.to.be.true;
		expect(
			verifyRemoteHtlcSignatures(holder, holderSigner, point, htlcSignatures, n)
		).to.be.true;
		expect(htlcSignatures.length).to.equal(K);
		return {
			txHex: built.result.tx.toHex(),
			txidInternal: built.result.tx.getHash(),
			sig: signature,
			htlcSigs: htlcSignatures
		};
	};
	const rView = view(sState, rState, sSigner, rSigner, rPoint, N_R + 1n);
	const sView = view(rState, sState, rSigner, sSigner, sPoint, N0 + 1n);

	const hCommit = computeHCommit(
		N_R + 1n,
		rView.txidInternal,
		N0 + 1n,
		sView.txidInternal
	);
	const activateBody = signFforMessage(
		FF_ACTIVATE_TYPE,
		encodeFforActivateUnsigned({
			channelId: CHANNEL_ID,
			epochId,
			setupHash: tSetup,
			bookHash: hBook,
			commitHash: hCommit,
			epochStartHeight: EPOCH_START_HEIGHT
		}),
		R_NODE_PRIV
	);
	const activateWire = fforWireBytes(FF_ACTIVATE_TYPE, activateBody);
	const hAct = computeHAct(tSetup, hBook, hCommit, EPOCH_START_HEIGHT);
	const ackBody = signFforMessage(
		FF_ACTIVATE_ACK_TYPE,
		encodeFforActivateAckUnsigned({
			channelId: CHANNEL_ID,
			epochId,
			activationHash: hAct
		}),
		S_NODE_PRIV
	);
	const ackWire = fforWireBytes(FF_ACTIVATE_ACK_TYPE, ackBody);

	return {
		epochId,
		hashes,
		preimages,
		initBody,
		initWire,
		tInit,
		acceptBody,
		acceptWire,
		tSetup,
		book,
		hBook,
		rView,
		sView,
		hCommit,
		activateBody,
		activateWire,
		hAct,
		ackBody,
		ackWire
	};
}

describe('FFOR Appendix D: Variant D setup vectors', function () {
	this.timeout(60_000);

	for (const sc of SCENARIOS) {
		describe(`${sc.id}: K = ${sc.amounts.length}, funder ${sc.funder}`, () => {
			let b: IBuilt;
			before(() => {
				b = buildScenario(sc);
			});

			it('derives the fixture epoch_id', () => {
				expect(b.epochId.toString('hex')).to.equal(sc.epochId);
			});

			it('ff_init: signature, wire digest and T_init', () => {
				expect(
					b.initBody.subarray(b.initBody.length - 64).toString('hex')
				).to.equal(sc.initSig);
				expect(sha256(b.initWire).toString('hex')).to.equal(sc.initWireSha256);
				expect(b.tInit.toString('hex')).to.equal(sc.tInit);
				expect(verifyFforMessage(FF_INIT_TYPE, b.initBody, R_NODE_PUB)).to.be
					.true;
				expect(verifyFforMessage(FF_INIT_TYPE, b.initBody, S_NODE_PUB)).to.be
					.false;
				const d = decodeFforInitMessage(b.initBody);
				expect(d.variant).to.equal(4);
				expect(d.maxPayments).to.equal(sc.amounts.length);
				expect(d.voucherAmountsMsat).to.deep.equal(sc.amounts);
				expect(d.rPerCommitmentPoints.length).to.equal(0);
				expect(d.paymentHashes).to.be.undefined;
			});

			it('ff_accept: signature, wire digest and T_setup', () => {
				expect(
					b.acceptBody.subarray(b.acceptBody.length - 64).toString('hex')
				).to.equal(sc.acceptSig);
				expect(sha256(b.acceptWire).toString('hex')).to.equal(
					sc.acceptWireSha256
				);
				expect(b.tSetup.toString('hex')).to.equal(sc.tSetup);
				expect(verifyFforMessage(FF_ACCEPT_TYPE, b.acceptBody, S_NODE_PUB)).to
					.be.true;
				const d = decodeFforAcceptMessage(b.acceptBody);
				expect(d.sCommitmentNumber).to.equal(N0);
				expect(d.sHtlcIdBase).to.equal(sc.sHtlcIdBase);
				expect(d.initHash.equals(b.tInit)).to.be.true;
				expect(d.paymentHashes.length).to.equal(sc.amounts.length);
				expect(d.voucherAmountsMsat).to.deep.equal(sc.amounts);
			});

			it('the voucher book and H_book', () => {
				expect(b.book.length).to.equal(36 + 58 * sc.amounts.length);
				expect(b.hBook.toString('hex')).to.equal(sc.hBook);
			});

			it('the setup checks pass on the fixture channel', () => {
				expect(
					checkVoucherBook(
						{
							variant: FforVariant.D,
							budgetMsat: sc.amounts.reduce((a, c) => a + c, 0n),
							maxPayments: sc.amounts.length,
							minPaymentMsat: MIN_PAYMENT_MSAT,
							settlementDeadline: D_DEADLINE,
							voucherExpiry: T_EXP,
							feeBaseMsat: FEE_BASE_MSAT,
							feeProportionalMillionths: FEE_PROP_MILLIONTHS,
							escapeGranularityMsat: 0n,
							rPerCommitmentPoints: [],
							voucherAmountsMsat: sc.amounts
						},
						{
							rMaxAcceptedHtlcs: MAX_ACCEPTED_HTLCS,
							rMaxHtlcValueInFlightMsat: MAX_HTLC_VALUE_IN_FLIGHT_MSAT,
							htlcMinimumMsat: HTLC_MINIMUM_MSAT,
							dustLimitSatoshis: DUST_LIMIT_SAT,
							feeratePerKw: FEERATE_PER_KW,
							sLocalBalanceMsat: S_BALANCE_MSAT_PRE,
							rLocalBalanceMsat: R_BALANCE_MSAT_PRE,
							sChannelReserveSat: CHANNEL_RESERVE_SAT,
							rChannelReserveSat: CHANNEL_RESERVE_SAT,
							sIsFunder: sc.funder === 'S',
							anchors: true
						}
					)
				).to.equal(null);
			});

			it("both commitment views: txids and the counterparty's signatures", () => {
				expect(b.rView.txidInternal.toString('hex')).to.equal(sc.rTxidInternal);
				expect(b.sView.txidInternal.toString('hex')).to.equal(sc.sTxidInternal);
				expect(b.rView.sig.toString('hex')).to.equal(sc.rViewCommitSig);
				expect(b.sView.sig.toString('hex')).to.equal(sc.sViewCommitSig);
			});

			it('H_commit, ff_activate, H_act and ff_activate_ack', () => {
				expect(b.hCommit.toString('hex')).to.equal(sc.hCommit);
				expect(
					b.activateBody.subarray(b.activateBody.length - 64).toString('hex')
				).to.equal(sc.activateSig);
				expect(sha256(b.activateWire).toString('hex')).to.equal(
					sc.activateWireSha256
				);
				expect(b.hAct.toString('hex')).to.equal(sc.hAct);
				expect(
					b.ackBody.subarray(b.ackBody.length - 64).toString('hex')
				).to.equal(sc.ackSig);
				expect(sha256(b.ackWire).toString('hex')).to.equal(sc.ackWireSha256);
				const a = decodeFforActivateMessage(b.activateBody);
				expect(a.setupHash.equals(b.tSetup)).to.be.true;
				expect(a.bookHash.equals(b.hBook)).to.be.true;
				expect(a.commitHash.equals(b.hCommit)).to.be.true;
				expect(a.epochStartHeight).to.equal(EPOCH_START_HEIGHT);
				const ack = decodeFforActivateAckMessage(b.ackBody);
				expect(ack.activationHash.equals(b.hAct)).to.be.true;
				expect(verifyFforMessage(FF_ACTIVATE_TYPE, b.activateBody, R_NODE_PUB))
					.to.be.true;
				expect(verifyFforMessage(FF_ACTIVATE_ACK_TYPE, b.ackBody, S_NODE_PUB))
					.to.be.true;
			});

			it('H_1 is not the hash of any secret S has revealed (7.2)', () => {
				for (let n = 0n; n <= N0; n++) {
					expect(sha256(pcSecret(S_PC_SEED, n)).equals(b.hashes[0])).to.be
						.false;
				}
			});
		});
	}

	describe('D.1 whole-wire comparison', () => {
		let b: IBuilt;
		before(() => {
			b = buildScenario(SCENARIOS[0]);
		});

		it('ff_init, ff_accept, ff_activate, ff_activate_ack wire bytes', () => {
			expect(b.initWire.toString('hex')).to.equal(D1_INIT_WIRE);
			expect(b.acceptWire.toString('hex')).to.equal(D1_ACCEPT_WIRE);
			expect(b.activateWire.toString('hex')).to.equal(D1_ACTIVATE_WIRE);
			expect(b.ackWire.toString('hex')).to.equal(D1_ACK_WIRE);
		});

		it('the book bytes, voucher hash and preimage', () => {
			expect(b.book.toString('hex')).to.equal(D1_BOOK);
			expect(b.hashes[0].toString('hex')).to.equal(D1_VOUCHER1_HASH);
			expect(b.preimages[0].toString('hex')).to.equal(D1_VOUCHER1_PREIMAGE);
		});

		it('both commitment transactions and the second-stage signatures', () => {
			expect(b.rView.txHex).to.equal(D1_R_VIEW_TX);
			expect(b.sView.txHex).to.equal(D1_S_VIEW_TX);
			expect(b.rView.htlcSigs[0].toString('hex')).to.equal(D1_R_VIEW_HTLC_SIG);
			expect(b.sView.htlcSigs[0].toString('hex')).to.equal(D1_S_VIEW_HTLC_SIG);
		});

		it('the voucher onion: payload secret, ephemeral key and update_add_htlc bytes', () => {
			const secret = voucherPaymentSecret(b.epochId, 1);
			expect(secret.toString('hex')).to.equal(D1_VOUCHER1_SECRET);
			const sessionKey = sha256(
				Buffer.concat([ascii('ffor/vector/onion-session'), b.epochId, u16(1)])
			);
			expect(sessionKey.toString('hex')).to.equal(D1_VOUCHER1_SESSION);
			const onion = buildVoucherOnion({
				recipientNodeId: R_NODE_PUB,
				epochId: b.epochId,
				k: 1,
				amountMsat: 1_000_000n,
				voucherExpiry: T_EXP,
				paymentHash: b.hashes[0],
				sessionKey
			});
			expect(onion.length).to.equal(1366);
			expect(onion.subarray(1, 34).toString('hex')).to.equal(
				D1_VOUCHER1_EPHEMERAL
			);
			const add = Buffer.concat([h2b(D1_ADD_HTLC_PREFIX), onion]);
			expect(add.length).to.equal(1452);
			// The appendix prints the whole add; its onion is what we built.
			const processed = processOnionPacket(
				decodeOnionPacket(onion),
				R_NODE_PRIV,
				b.hashes[0]
			);
			expect(isFinalHop(processed.nextPacket)).to.be.true;
			expect(processed.hopPayload.amountToForwardMsat).to.equal(1_000_000n);
			expect(processed.hopPayload.outgoingCltvValue).to.equal(T_EXP);
			expect(processed.hopPayload.paymentSecret!.equals(secret)).to.be.true;
			expect(processed.hopPayload.totalMsat).to.equal(1_000_000n);
			expect(processed.hopPayload.shortChannelId).to.be.undefined;
			// And the generator's direct construction agrees byte for byte.
			const direct = encodeOnionPacket(
				constructOnionPacket(
					sessionKey,
					[
						{
							pubkey: R_NODE_PUB,
							payload: {
								amountToForwardMsat: 1_000_000n,
								outgoingCltvValue: T_EXP,
								paymentSecret: secret,
								totalMsat: 1_000_000n
							}
						}
					],
					b.hashes[0]
				)
			);
			expect(onion.equals(direct)).to.be.true;
		});

		it('fee_S and gross_into_S for voucher 1', () => {
			expect(feeS(1_000_000n, FEE_BASE_MSAT, FEE_PROP_MILLIONTHS)).to.equal(
				6000n
			);
			expect(
				grossIntoS(1_000_000n, FEE_BASE_MSAT, FEE_PROP_MILLIONTHS)
			).to.equal(1_006_000n);
		});
	});

	describe('D.4.9 the refused amount', () => {
		it('545,999 msat fails both the min_payment_msat and the trim check', () => {
			const err = checkVoucherBook(
				{
					variant: FforVariant.D,
					budgetMsat: 545_999n,
					maxPayments: 1,
					minPaymentMsat: MIN_PAYMENT_MSAT,
					settlementDeadline: D_DEADLINE,
					voucherExpiry: T_EXP,
					feeBaseMsat: FEE_BASE_MSAT,
					feeProportionalMillionths: FEE_PROP_MILLIONTHS,
					escapeGranularityMsat: 0n,
					rPerCommitmentPoints: [],
					voucherAmountsMsat: [545_999n]
				},
				{
					rMaxAcceptedHtlcs: MAX_ACCEPTED_HTLCS,
					rMaxHtlcValueInFlightMsat: MAX_HTLC_VALUE_IN_FLIGHT_MSAT,
					htlcMinimumMsat: HTLC_MINIMUM_MSAT,
					dustLimitSatoshis: DUST_LIMIT_SAT,
					feeratePerKw: FEERATE_PER_KW,
					sLocalBalanceMsat: S_BALANCE_MSAT_PRE,
					rLocalBalanceMsat: R_BALANCE_MSAT_PRE,
					sChannelReserveSat: CHANNEL_RESERVE_SAT,
					rChannelReserveSat: CHANNEL_RESERVE_SAT,
					sIsFunder: true,
					anchors: true
				}
			);
			expect(err).to.include('min_payment_msat');
			const trim = checkVoucherBook(
				{
					variant: FforVariant.D,
					budgetMsat: 545_999n,
					maxPayments: 1,
					minPaymentMsat: 1n,
					settlementDeadline: D_DEADLINE,
					voucherExpiry: T_EXP,
					feeBaseMsat: FEE_BASE_MSAT,
					feeProportionalMillionths: FEE_PROP_MILLIONTHS,
					escapeGranularityMsat: 0n,
					rPerCommitmentPoints: [],
					voucherAmountsMsat: [545_999n]
				},
				{
					rMaxAcceptedHtlcs: MAX_ACCEPTED_HTLCS,
					rMaxHtlcValueInFlightMsat: MAX_HTLC_VALUE_IN_FLIGHT_MSAT,
					htlcMinimumMsat: HTLC_MINIMUM_MSAT,
					dustLimitSatoshis: DUST_LIMIT_SAT,
					feeratePerKw: FEERATE_PER_KW,
					sLocalBalanceMsat: S_BALANCE_MSAT_PRE,
					rLocalBalanceMsat: R_BALANCE_MSAT_PRE,
					sChannelReserveSat: CHANNEL_RESERVE_SAT,
					rChannelReserveSat: CHANNEL_RESERVE_SAT,
					sIsFunder: true,
					anchors: true
				}
			);
			expect(trim).to.include('trim');
		});
	});
});
