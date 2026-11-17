/**
 * An ordinary channel ends on chain as it did before asset channels existed
 * (issue #2093): a force close by either side with five HTLCs in flight, and
 * an old, revoked commitment of either side put on the chain, for the three
 * kinds of ordinary channel. Both nodes follow a chain through their own
 * watcher until nothing is left to do.
 *
 * The digests were captured from the source of the previous release
 * (4fdaeb60) by running tests/lightning/helpers/ordinary-force-close.ts
 * against it under the same counter in place of randomness. They cover the
 * outputs each node tracked once the commitment confirmed and at the end,
 * the bytes of every transaction each node handed on to be published in the
 * order it did, what the chain would not take, and every monitor row stored.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { ChannelManager } from '../../src/lightning/channel/channel-manager';
import { ChainWatcher } from '../../src/lightning/chain/chain-watcher';
import { signRemoteCommitment } from '../../src/lightning/channel/commitment-builder';
import { isTaprootChannel } from '../../src/lightning/channel/types';
import { randomBytes } from '../../src/lightning/crypto/provider';
import { createFundingScript } from '../../src/lightning/script/funding';
import { createTaprootFundingScript } from '../../src/lightning/script/funding-taproot';
import {
	serializeChainMonitorState,
	serializeChannelState
} from '../../src/lightning/storage/serialization';
import type {
	IOrdinaryForceCloseDigests,
	IOrdinaryForceCloseEngine,
	IOrdinaryForceCloseSide
} from './helpers/ordinary-force-close';
import { ordinaryForceClose } from './helpers/ordinary-force-close';
import { configOf, privAt, seedFor } from './helpers/taproot-revoked-fixture';
import { ORDINARY_NODES } from './helpers/untouchable-provider';

const ENGINE: IOrdinaryForceCloseEngine = {
	ChannelManager,
	ChainWatcher,
	configOf,
	seedFor,
	privAt,
	signRemoteCommitment,
	isTaprootChannel,
	serializeChannelState,
	serializeChainMonitorState,
	createFundingScript,
	createTaprootFundingScript,
	randomBytes
};

interface IGoldenSide {
	/** How many transactions the node handed on, and a digest of their bytes in order. */
	published: number;
	bytes: string;
	/** How many of them the chain would not take, and a digest of which and why. */
	refused: number;
	refusals: string;
	trackedAtClose: string;
	rowsAtClose: string;
	trackedAtEnd: string;
	rowsAtEnd: string;
	resolved: boolean;
}

interface IGolden {
	alice: IGoldenSide;
	bob: IGoldenSide;
	monitorRowsStored: number;
	monitorRows: string;
	height: number;
}

const reduceSide = (side: IOrdinaryForceCloseSide): IGoldenSide => ({
	published: side.order === '' ? 0 : side.order.split(' ').length,
	bytes: side.bytes,
	refused: side.refused.length,
	refusals: crypto
		.createHash('sha256')
		.update(side.refused.join('\n'))
		.digest('hex'),
	trackedAtClose: side.trackedAtClose,
	rowsAtClose: side.rowsAtClose,
	trackedAtEnd: side.trackedAtEnd,
	rowsAtEnd: side.rowsAtEnd,
	resolved: side.resolved
});

const reduce = (ended: IOrdinaryForceCloseDigests): IGolden => ({
	alice: reduceSide(ended.alice),
	bob: reduceSide(ended.bob),
	monitorRowsStored: ended.monitorRowsStored,
	monitorRows: ended.monitorRows,
	height: ended.height
});

const GOLDEN: Record<string, IGolden> = {
	'static_remotekey:current:alice': {
		alice: {
			published: 44,
			bytes: '401c3b7f3cc216d5dc20ad07b30ca58e871389341d8917e5e2d44edbc61f33fa',
			refused: 38,
			refusals:
				'225e81e1d2fe4d289c694074998e267f7a3110c846bf4cd4438cae434457b7ab',
			trackedAtClose:
				'OFFERED_HTLC:CONFIRMED RECEIVED_HTLC:SPEND_BROADCAST RECEIVED_HTLC:CONFIRMED OFFERED_HTLC:SPEND_CONFIRMED TO_REMOTE:SPEND_CONFIRMED TO_LOCAL:CONFIRMED',
			rowsAtClose:
				'adcda0acf9ad22d3d1856b987e512349360b780dcaf61c8b5f93e525aed8eb4a',
			trackedAtEnd:
				'OFFERED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED TO_REMOTE:IRREVOCABLY_RESOLVED TO_LOCAL:IRREVOCABLY_RESOLVED TO_LOCAL:IRREVOCABLY_RESOLVED TO_LOCAL:IRREVOCABLY_RESOLVED',
			rowsAtEnd:
				'9a5e2b3286c60b092aa5f81787e50ff50af29dc16a3ab32a4e82b58833bb55a8',
			resolved: true
		},
		bob: {
			published: 29,
			bytes: '23c3a0757b78c3a09248ca9eb5966304876d67600395507338945d734b1d27b8',
			refused: 26,
			refusals:
				'f12b9b1026b51553dd40cb4d42de2092f34f8ad32c337f357b53b467a554e9b8',
			trackedAtClose:
				'RECEIVED_HTLC:CONFIRMED OFFERED_HTLC:CONFIRMED OFFERED_HTLC:CONFIRMED RECEIVED_HTLC:SPEND_CONFIRMED TO_REMOTE:SPEND_CONFIRMED TO_LOCAL:CONFIRMED',
			rowsAtClose:
				'5a710db5fc26b40a6dce71d475f0460af786c716388a3222dd4a8c3378faa2d3',
			trackedAtEnd:
				'RECEIVED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED TO_REMOTE:IRREVOCABLY_RESOLVED TO_LOCAL:SPEND_CONFIRMED',
			rowsAtEnd:
				'ca72bee2b8f6fc0f4ae31ad577e8b50089a237951a9d6f966764574dde35d690',
			resolved: true
		},
		monitorRowsStored: 373,
		monitorRows:
			'd93ef0b09274ab094f5a45e8e31c61be1e43a61d2b1377294ab3398ed0690242',
		height: 447
	},
	'static_remotekey:current:bob': {
		alice: {
			published: 29,
			bytes: 'bb5b5be367d0a7f8f709e8f4f75feb4d26621e6ecf7c9310d98587aaf31592b5',
			refused: 26,
			refusals:
				'7ec7413a535384fc81652d066f034197b50fd05d40cd68e78a597f370dc30663',
			trackedAtClose:
				'OFFERED_HTLC:CONFIRMED RECEIVED_HTLC:SPEND_CONFIRMED RECEIVED_HTLC:CONFIRMED OFFERED_HTLC:CONFIRMED TO_LOCAL:CONFIRMED TO_REMOTE:SPEND_CONFIRMED',
			rowsAtClose:
				'0795154c910714e51c3a309e8e86fe6d723c503fa33af6924f63a00a94235847',
			trackedAtEnd:
				'OFFERED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED TO_LOCAL:SPEND_CONFIRMED TO_REMOTE:IRREVOCABLY_RESOLVED',
			rowsAtEnd:
				'c3676bd3e47c6924602e718b4dd1b89296c2622e8beabfb50994aee4704d0f18',
			resolved: true
		},
		bob: {
			published: 44,
			bytes: 'dfabc79683749371a614cf14a0f062aa7d04d25b32338e2d8a884e75e72e4ece',
			refused: 38,
			refusals:
				'b4750d837f60830709f150d09f442214cfe9160b16f8f823c618856b005da23f',
			trackedAtClose:
				'RECEIVED_HTLC:CONFIRMED OFFERED_HTLC:SPEND_CONFIRMED OFFERED_HTLC:CONFIRMED RECEIVED_HTLC:SPEND_BROADCAST TO_LOCAL:CONFIRMED TO_REMOTE:SPEND_CONFIRMED',
			rowsAtClose:
				'662eaf48cd186a2d5d2b1da73a56a0a9a8790f38f524df9d481f42ac687a78b6',
			trackedAtEnd:
				'RECEIVED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED TO_LOCAL:IRREVOCABLY_RESOLVED TO_REMOTE:IRREVOCABLY_RESOLVED TO_LOCAL:IRREVOCABLY_RESOLVED TO_LOCAL:IRREVOCABLY_RESOLVED',
			rowsAtEnd:
				'ea7d69ebb7b593a5d001d9f4d795aa227cacc265c0d9850d68e5a9742668d493',
			resolved: true
		},
		monitorRowsStored: 373,
		monitorRows:
			'99511d601cb5087562059052de7553b2100b75239746411dee4394247053359d',
		height: 447
	},
	'static_remotekey:revoked:alice': {
		alice: {
			published: 0,
			bytes: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
			refused: 0,
			refusals:
				'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
			trackedAtClose: '',
			rowsAtClose:
				'4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
			trackedAtEnd: '',
			rowsAtEnd:
				'4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
			resolved: false
		},
		bob: {
			published: 28,
			bytes: 'ebec7acea51b6c56341443c612a13870d33717839f47c33b5734858a76a4ef6c',
			refused: 26,
			refusals:
				'd62a403a090f15677c66e9eafcfec22543aad668f79fb178c90a2b33d226f075',
			trackedAtClose:
				'RECEIVED_HTLC:SPEND_CONFIRMED OFFERED_HTLC:SPEND_CONFIRMED OFFERED_HTLC:SPEND_CONFIRMED RECEIVED_HTLC:SPEND_CONFIRMED TO_REMOTE:SPEND_CONFIRMED TO_LOCAL:SPEND_CONFIRMED',
			rowsAtClose:
				'da27caed28868e07a0c3e35229609d8735dff482a1dbfa4ea7f7cd47054d35c6',
			trackedAtEnd:
				'RECEIVED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED TO_REMOTE:IRREVOCABLY_RESOLVED TO_LOCAL:IRREVOCABLY_RESOLVED',
			rowsAtEnd:
				'7c195d4d894a8b5e0be14576cf932b8b89b0baf9bd2c4624af480c789f70446d',
			resolved: true
		},
		monitorRowsStored: 346,
		monitorRows:
			'99728ea8c6d697293e30016180f86e842c4229ec8cf2307280816486cc326b49',
		height: 447
	},
	'static_remotekey:revoked:bob': {
		alice: {
			published: 28,
			bytes: '2640677d7477b14c42ff2b7fbd4b33c58561ecc1ff6ff0b82cfdfd24a4eba619',
			refused: 26,
			refusals:
				'5e051009d27c7fac6a7c0dd164078a206745c18c58d874fef1aff2be91d40ec5',
			trackedAtClose:
				'OFFERED_HTLC:SPEND_CONFIRMED RECEIVED_HTLC:SPEND_CONFIRMED RECEIVED_HTLC:SPEND_CONFIRMED OFFERED_HTLC:SPEND_CONFIRMED TO_LOCAL:SPEND_CONFIRMED TO_REMOTE:SPEND_CONFIRMED',
			rowsAtClose:
				'6fed261c32ca63110a84d69e5d404bd6674a8915606d5065ce281e25c04a0ad2',
			trackedAtEnd:
				'OFFERED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED TO_LOCAL:IRREVOCABLY_RESOLVED TO_REMOTE:IRREVOCABLY_RESOLVED',
			rowsAtEnd:
				'711e8125096897e9c60947cc9401145b0c159826313d03ea3b72ed27e9467446',
			resolved: true
		},
		bob: {
			published: 0,
			bytes: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
			refused: 0,
			refusals:
				'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
			trackedAtClose: '',
			rowsAtClose:
				'4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
			trackedAtEnd: '',
			rowsAtEnd:
				'4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
			resolved: false
		},
		monitorRowsStored: 346,
		monitorRows:
			'ce545643cef4839097062dbdcdbe50273045c885570b4c31cf76525aec3944ef',
		height: 447
	},
	'anchors:current:alice': {
		alice: {
			published: 46,
			bytes: '96c7481e160c6fa30e22cfca2eddc08aa0b0cac5e38d164d2768099b44cee29f',
			refused: 38,
			refusals:
				'22237a07f91182741ddfb1a4aa535dac241da2a5010b95204720e1964dd822e5',
			trackedAtClose:
				'OFFERED_HTLC:CONFIRMED OFFERED_HTLC:CONFIRMED RECEIVED_HTLC:CONFIRMED RECEIVED_HTLC:CONFIRMED OFFERED_HTLC:CONFIRMED TO_REMOTE:CONFIRMED TO_LOCAL:CONFIRMED',
			rowsAtClose:
				'5cc358c87ed060608e5a57565617289f84498422b6f4b46af1fa328b11f5ebfa',
			trackedAtEnd:
				'OFFERED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED TO_REMOTE:IRREVOCABLY_RESOLVED TO_LOCAL:IRREVOCABLY_RESOLVED TO_LOCAL:IRREVOCABLY_RESOLVED TO_LOCAL:CONFIRMED TO_LOCAL:IRREVOCABLY_RESOLVED',
			rowsAtEnd:
				'8de2eee58b45c4b88b7b32f87a330854997fcc9a79eea1cd9ce7cd4b686a9641',
			resolved: false
		},
		bob: {
			published: 4,
			bytes: '38f932e8fde904a68923ef2b5167e5f02e304d63476d303917ec444e020da834',
			refused: 0,
			refusals:
				'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
			trackedAtClose:
				'RECEIVED_HTLC:CONFIRMED RECEIVED_HTLC:CONFIRMED OFFERED_HTLC:CONFIRMED OFFERED_HTLC:CONFIRMED RECEIVED_HTLC:CONFIRMED TO_REMOTE:CONFIRMED TO_LOCAL:CONFIRMED',
			rowsAtClose:
				'121bcc6718a6e9515343816ac3d2848765d4de6ad0c22ae5e7d1069eea347670',
			trackedAtEnd:
				'RECEIVED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED TO_REMOTE:IRREVOCABLY_RESOLVED TO_LOCAL:SPEND_CONFIRMED',
			rowsAtEnd:
				'68bdb60d2e178c146d402b62257b8a0f3c0c59067f9557425831577cd9561ab2',
			resolved: true
		},
		monitorRowsStored: 378,
		monitorRows:
			'7ff95a3631b91811228cb8b496156a7313f52652b4d1b80fdbace7f6739551f6',
		height: 447
	},
	'anchors:current:bob': {
		alice: {
			published: 4,
			bytes: 'c491715c97bd37297adbe07d70fb28a46a15e1ce9b914d4e20f4d33fb7f648bc',
			refused: 0,
			refusals:
				'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
			trackedAtClose:
				'OFFERED_HTLC:CONFIRMED OFFERED_HTLC:CONFIRMED RECEIVED_HTLC:CONFIRMED RECEIVED_HTLC:CONFIRMED OFFERED_HTLC:CONFIRMED TO_LOCAL:CONFIRMED TO_REMOTE:CONFIRMED',
			rowsAtClose:
				'b2f427a8d98ae9b368d5891658aa3b3eea4e38a1d58b2a668fcd678768032aa3',
			trackedAtEnd:
				'OFFERED_HTLC:CONFIRMED OFFERED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED TO_LOCAL:IRREVOCABLY_RESOLVED TO_REMOTE:IRREVOCABLY_RESOLVED',
			rowsAtEnd:
				'94353941781db9bad7135b8a0d3a547c5d099b99553d26d25b93f26339e2e35a',
			resolved: false
		},
		bob: {
			published: 45,
			bytes: '9110b894971eec8d54a428eb5391cd96f95df56565a8ee40543415b28bd2c5c6',
			refused: 38,
			refusals:
				'a23d2693d948f1d98d24acb32b07807546639e26868cf12e8c7833342c5c744a',
			trackedAtClose:
				'RECEIVED_HTLC:CONFIRMED RECEIVED_HTLC:CONFIRMED OFFERED_HTLC:CONFIRMED OFFERED_HTLC:CONFIRMED RECEIVED_HTLC:CONFIRMED TO_LOCAL:CONFIRMED TO_REMOTE:CONFIRMED',
			rowsAtClose:
				'33bac408dc7728ce34e682236005b2dc369ae6d119199450c9f61cd884c9b89e',
			trackedAtEnd:
				'RECEIVED_HTLC:CONFIRMED RECEIVED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED TO_LOCAL:IRREVOCABLY_RESOLVED TO_REMOTE:IRREVOCABLY_RESOLVED TO_LOCAL:IRREVOCABLY_RESOLVED TO_LOCAL:IRREVOCABLY_RESOLVED',
			rowsAtEnd:
				'815c01d091eec42694d182320c0db9d9a723d930a4a88061d26b6b1f0ea6fe1a',
			resolved: false
		},
		monitorRowsStored: 391,
		monitorRows:
			'64ad72260fa9bae5e97c240771488d2ce4eb40b1c20db3cf5f0cb99b9ca992f9',
		height: 447
	},
	'anchors:revoked:alice': {
		alice: {
			published: 1,
			bytes: 'ea3576b70df603927f7ff46d7cac8c30a698b40f6dce2b34758cc0c8ffa8c4b1',
			refused: 0,
			refusals:
				'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
			trackedAtClose: '',
			rowsAtClose:
				'4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
			trackedAtEnd: '',
			rowsAtEnd:
				'4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
			resolved: false
		},
		bob: {
			published: 19,
			bytes: '1a4dc7137226ba30044fa40453a2fae7e7bf231491fe15b5d58a2909b2d24173',
			refused: 14,
			refusals:
				'2d5608a1b07248f28195c7d5a5dbeacabfcecb2df179d806d7b4f2db1fd94765',
			trackedAtClose:
				'RECEIVED_HTLC:SPEND_CONFIRMED RECEIVED_HTLC:SPEND_CONFIRMED OFFERED_HTLC:SPEND_CONFIRMED OFFERED_HTLC:SPEND_CONFIRMED RECEIVED_HTLC:SPEND_CONFIRMED TO_REMOTE:CONFIRMED TO_LOCAL:SPEND_CONFIRMED',
			rowsAtClose:
				'6962405764f17c2a017fdd355e78598cd610616515352245ee4c6ce0b4e0e016',
			trackedAtEnd:
				'RECEIVED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED TO_REMOTE:IRREVOCABLY_RESOLVED TO_LOCAL:IRREVOCABLY_RESOLVED',
			rowsAtEnd:
				'7a0cb0cb386fee2a76ca1321493d2f1a45c6d7c600d8fc1ebdfc5c95e2fbdcdb',
			resolved: true
		},
		monitorRowsStored: 350,
		monitorRows:
			'13abefcbd30c24c40d741dabaa216f4497f6f6d5b5fd7a2cc2c16de936eb2f47',
		height: 447
	},
	'anchors:revoked:bob': {
		alice: {
			published: 19,
			bytes: '2c044a9de2cd286f2388842e5011432db005e5963beb523daf63e8a5f9a91afe',
			refused: 14,
			refusals:
				'fc25b8194b15bd5c9c5b4a168615710dcdbc228221478b5ea86043e0817a2014',
			trackedAtClose:
				'OFFERED_HTLC:SPEND_CONFIRMED OFFERED_HTLC:SPEND_CONFIRMED RECEIVED_HTLC:SPEND_CONFIRMED RECEIVED_HTLC:SPEND_CONFIRMED OFFERED_HTLC:SPEND_CONFIRMED TO_LOCAL:SPEND_CONFIRMED TO_REMOTE:CONFIRMED',
			rowsAtClose:
				'0ee648267965b17a17f6c2a30dd5185b172503db604a2b5950c0f28da51e0ad8',
			trackedAtEnd:
				'OFFERED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED TO_LOCAL:IRREVOCABLY_RESOLVED TO_REMOTE:IRREVOCABLY_RESOLVED',
			rowsAtEnd:
				'fb959b4cd9504857e3bb8ab9065d8a86a9949a54ceac492b6d21206de9489ee5',
			resolved: true
		},
		bob: {
			published: 1,
			bytes: '1af54b8ae272beca514ece3d8d567d434345546c6404a61a2d52e89c47ba2b53',
			refused: 0,
			refusals:
				'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
			trackedAtClose: '',
			rowsAtClose:
				'4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
			trackedAtEnd: '',
			rowsAtEnd:
				'4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
			resolved: false
		},
		monitorRowsStored: 350,
		monitorRows:
			'733b6592f67689ee2e720e012a1642b388ac9d61e54843aefe23b5e67db8bf14',
		height: 447
	},
	'taproot:current:alice': {
		alice: {
			published: 46,
			bytes: '108b15110ab265f6db12bb3bf8bce0549042f51d1f93aed3d4b3200e0b39a6c5',
			refused: 38,
			refusals:
				'ac8a56a72a07c38e0cd7d316b49f17b6b5912b2abc40cd8b69046916af9c976c',
			trackedAtClose:
				'OFFERED_HTLC:CONFIRMED OFFERED_HTLC:CONFIRMED RECEIVED_HTLC:CONFIRMED RECEIVED_HTLC:CONFIRMED OFFERED_HTLC:CONFIRMED TO_REMOTE:CONFIRMED TO_LOCAL:CONFIRMED',
			rowsAtClose:
				'8310735b4ee579fb35caa7b1c9e90d17b2f1d188a8fbfd47538d4b3eafd4c768',
			trackedAtEnd:
				'OFFERED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED TO_REMOTE:IRREVOCABLY_RESOLVED TO_LOCAL:IRREVOCABLY_RESOLVED TO_LOCAL:IRREVOCABLY_RESOLVED TO_LOCAL:CONFIRMED TO_LOCAL:IRREVOCABLY_RESOLVED',
			rowsAtEnd:
				'180985dc561ed6dc105e0b7c7e4ac8376914fa8b552a91d7b2ca4e115d271974',
			resolved: false
		},
		bob: {
			published: 4,
			bytes: 'f50c6330336834b74400c75a6e20a412c4c56d8e08f2bfc180324a37f9b41bbb',
			refused: 0,
			refusals:
				'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
			trackedAtClose:
				'RECEIVED_HTLC:CONFIRMED RECEIVED_HTLC:CONFIRMED OFFERED_HTLC:CONFIRMED OFFERED_HTLC:CONFIRMED RECEIVED_HTLC:CONFIRMED TO_REMOTE:CONFIRMED TO_LOCAL:CONFIRMED',
			rowsAtClose:
				'c61ffb4d7c102126b18739689346727c798d84993c4c7f76aee2cc264f0600c3',
			trackedAtEnd:
				'RECEIVED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED TO_REMOTE:IRREVOCABLY_RESOLVED TO_LOCAL:SPEND_CONFIRMED',
			rowsAtEnd:
				'ba17581a61f354e031d96b4ff90ac6cb19263f23643518d64a6e52da24ede452',
			resolved: true
		},
		monitorRowsStored: 378,
		monitorRows:
			'8c62935603cdd1168e6b34642f7b2e18be52ee18b3df0679f9ee4e872ae7ed73',
		height: 447
	},
	'taproot:current:bob': {
		alice: {
			published: 4,
			bytes: '877009de084a83762d843fc0ff57a4169e5169e53dd1ddc4542506f885d33afc',
			refused: 0,
			refusals:
				'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
			trackedAtClose:
				'OFFERED_HTLC:CONFIRMED OFFERED_HTLC:CONFIRMED RECEIVED_HTLC:CONFIRMED RECEIVED_HTLC:CONFIRMED OFFERED_HTLC:CONFIRMED TO_LOCAL:CONFIRMED TO_REMOTE:CONFIRMED',
			rowsAtClose:
				'b34b84a1e2bdb921c2104c3ecac301790389ae28226e922de16e94fc5d9f2d18',
			trackedAtEnd:
				'OFFERED_HTLC:CONFIRMED OFFERED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED TO_LOCAL:IRREVOCABLY_RESOLVED TO_REMOTE:IRREVOCABLY_RESOLVED',
			rowsAtEnd:
				'7c1118b96e7c3dd76b64921eec5042fbcbef2a3c0fdf91cb2c7d349f91e638be',
			resolved: false
		},
		bob: {
			published: 45,
			bytes: 'dc0e4c3f35a95e7068f1078dc7191fde37ac2c8cb40781a4953104b23d22972e',
			refused: 38,
			refusals:
				'bdfa3dd624b3640025fb25e16089e64fc4ff64cd3d96fe0f30fc79abd5bc485b',
			trackedAtClose:
				'RECEIVED_HTLC:CONFIRMED RECEIVED_HTLC:CONFIRMED OFFERED_HTLC:CONFIRMED OFFERED_HTLC:CONFIRMED RECEIVED_HTLC:CONFIRMED TO_LOCAL:CONFIRMED TO_REMOTE:CONFIRMED',
			rowsAtClose:
				'7fa6d72bd4c839949f19ae09f701f696868e34b55a8c660ac948eda175117a53',
			trackedAtEnd:
				'RECEIVED_HTLC:CONFIRMED RECEIVED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED TO_LOCAL:IRREVOCABLY_RESOLVED TO_REMOTE:IRREVOCABLY_RESOLVED TO_LOCAL:IRREVOCABLY_RESOLVED TO_LOCAL:IRREVOCABLY_RESOLVED',
			rowsAtEnd:
				'7588e76edcd999c65f2291f8d500c7f9972e5cebb0651ef52bd21ac5bb67d467',
			resolved: false
		},
		monitorRowsStored: 391,
		monitorRows:
			'0a41071c0ea4c522bac4a013516e32bc9170d932e28d2e231408372331890dbe',
		height: 447
	},
	'taproot:revoked:alice': {
		alice: {
			published: 0,
			bytes: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
			refused: 0,
			refusals:
				'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
			trackedAtClose: '',
			rowsAtClose:
				'4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
			trackedAtEnd: '',
			rowsAtEnd:
				'4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
			resolved: false
		},
		bob: {
			published: 19,
			bytes: 'cfef26d22bcb893de037d89b755b62a895d134ca2dd889bd8f773ddf28a70d77',
			refused: 14,
			refusals:
				'fb2606b9e4b4c8f086425f56f5c84f757b18ceda677b64026aca5942b7461085',
			trackedAtClose:
				'RECEIVED_HTLC:SPEND_CONFIRMED RECEIVED_HTLC:SPEND_CONFIRMED OFFERED_HTLC:SPEND_CONFIRMED OFFERED_HTLC:SPEND_CONFIRMED RECEIVED_HTLC:SPEND_CONFIRMED TO_REMOTE:CONFIRMED TO_LOCAL:SPEND_CONFIRMED',
			rowsAtClose:
				'ca18cf47707056727f4f41faee52d32a7226feb8738450fee62c59adc7a12351',
			trackedAtEnd:
				'RECEIVED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED TO_REMOTE:IRREVOCABLY_RESOLVED TO_LOCAL:IRREVOCABLY_RESOLVED',
			rowsAtEnd:
				'babc6abb8b54c50a4ae3bb3240d08c9406ab702c13472e09fe0bc5c469760907',
			resolved: true
		},
		monitorRowsStored: 350,
		monitorRows:
			'347c7b31e4f112fe5423abc0fe40a381d6ae18a13e1ee2f67ead5fd4171d6916',
		height: 447
	},
	'taproot:revoked:bob': {
		alice: {
			published: 19,
			bytes: '527486b2e563a412b9a320f86353b4c84c82024ef4c68872acf7cb2161a8f335',
			refused: 14,
			refusals:
				'd4e648f2efeebb536b1d9aeea03c011c5494e547d0e3012308eca9a38c9341dc',
			trackedAtClose:
				'OFFERED_HTLC:SPEND_CONFIRMED OFFERED_HTLC:SPEND_CONFIRMED RECEIVED_HTLC:SPEND_CONFIRMED RECEIVED_HTLC:SPEND_CONFIRMED OFFERED_HTLC:SPEND_CONFIRMED TO_LOCAL:SPEND_CONFIRMED TO_REMOTE:CONFIRMED',
			rowsAtClose:
				'43b783f64deb2ccfb6a400a7c611ecd5ba0aa03a4319bae8f87469f26ce52df2',
			trackedAtEnd:
				'OFFERED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED TO_LOCAL:IRREVOCABLY_RESOLVED TO_REMOTE:IRREVOCABLY_RESOLVED',
			rowsAtEnd:
				'1b369fc9f706d3b8fe219896e2a6b5dd8b2117fc682c7e6f5f09e1cbca6debd5',
			resolved: true
		},
		bob: {
			published: 0,
			bytes: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
			refused: 0,
			refusals:
				'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
			trackedAtClose: '',
			rowsAtClose:
				'4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
			trackedAtEnd: '',
			rowsAtEnd:
				'4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
			resolved: false
		},
		monitorRowsStored: 350,
		monitorRows:
			'b6663b97dd5a3e644201e07716be8229a53270896b5f05b143f1fc613fb6b9a6',
		height: 447
	}
};

describe('an ordinary channel ends on chain as it did before (issue #2093)', function () {
	this.timeout(120_000);

	it('a taproot channel with a revoked commitment of bob put on the chain, while something else in the process draws randomness', async () => {
		// What made this file fail once in a full run. The counter that
		// stands in for randomness was one for the whole process, so a draw
		// by anything else while the scenario waited, such as a timer another
		// test file left behind, moved every later draw of the scenario by
		// one. The MuSig2 nonces of the commitment signatures are such draws.
		// The revoked commitment is kept with its witness in the monitor's
		// row, and nothing else that is compared here holds that witness.
		let drawing = true;
		const draw = (): void => {
			if (!drawing) return;
			crypto.randomBytes(32);
			setImmediate(draw);
		};
		setImmediate(draw);
		try {
			const ended = await ordinaryForceClose(
				ENGINE,
				'taproot',
				'revoked',
				'bob'
			);
			expect(ended.errors).to.deep.equal([]);
			expect(reduce(ended)).to.deep.equal(GOLDEN['taproot:revoked:bob']);
		} finally {
			drawing = false;
		}
	});

	for (const [who, extra] of ORDINARY_NODES) {
		for (const kind of ['static_remotekey', 'anchors', 'taproot'] as const) {
			for (const scenario of ['current', 'revoked'] as const) {
				for (const actor of ['alice', 'bob'] as const) {
					const what =
						scenario === 'current'
							? `force closed by ${actor}`
							: `with a revoked commitment of ${actor} put on the chain`;
					it(`a ${kind} channel between ${who}, ${what}`, async () => {
						const ended = await ordinaryForceClose(
							ENGINE,
							kind,
							scenario,
							actor,
							extra
						);
						expect(ended.errors).to.deep.equal([]);
						expect(reduce(ended)).to.deep.equal(
							GOLDEN[`${kind}:${scenario}:${actor}`]
						);
					});
				}
			}
		}
	}
});
