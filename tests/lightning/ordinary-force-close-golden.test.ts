/**
 * An ordinary channel ends on chain as it did before asset channels existed
 * (issue #2093): a force close by either side with five HTLCs in flight, and
 * an old, revoked commitment of either side put on the chain, for the three
 * kinds of ordinary channel. Both nodes follow a chain through their own
 * watcher until nothing is left to do.
 *
 * The digests were captured from the source of the previous release
 * (4fdaeb60) by running tests/lightning/helpers/ordinary-force-close.ts
 * against it under the same counter in place of randomness, and captured
 * again when sweeps came to be priced on their signed size (#2106): only
 * the bytes, the rows and the txids in the refusals moved. They cover the
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
			bytes: 'b5a338ba263bcbd2c25a3980675b5281296b2dad749b16c85782c336dcda9163',
			refused: 38,
			refusals:
				'e03dd7a28ef1bba4e006ee065ff83d08382cee15df154c9b6ba4a2bf35e65f5a',
			trackedAtClose:
				'OFFERED_HTLC:CONFIRMED RECEIVED_HTLC:SPEND_BROADCAST RECEIVED_HTLC:CONFIRMED OFFERED_HTLC:SPEND_CONFIRMED TO_REMOTE:SPEND_CONFIRMED TO_LOCAL:CONFIRMED',
			rowsAtClose:
				'a3d8bf287aa1158125e022f03bf92ef263bf289b64506ecdfbd0aad3e1894812',
			trackedAtEnd:
				'OFFERED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED TO_REMOTE:IRREVOCABLY_RESOLVED TO_LOCAL:IRREVOCABLY_RESOLVED TO_LOCAL:IRREVOCABLY_RESOLVED TO_LOCAL:IRREVOCABLY_RESOLVED',
			rowsAtEnd:
				'69944a6ab553a805c93c6a0f5fe945ad02091f9982866ea12f25fb9cdb68e955',
			resolved: true
		},
		bob: {
			published: 29,
			bytes: 'a1cc0d9fa50d43cd56c00143950980f2f1221e74949f4544278529d0e64308fa',
			refused: 26,
			refusals:
				'539410e63cef0424b0847ee97860ca0981e259672869229055df24cd3ec5305d',
			trackedAtClose:
				'RECEIVED_HTLC:CONFIRMED OFFERED_HTLC:CONFIRMED OFFERED_HTLC:CONFIRMED RECEIVED_HTLC:SPEND_CONFIRMED TO_REMOTE:SPEND_CONFIRMED TO_LOCAL:CONFIRMED',
			rowsAtClose:
				'1f6855ada4db4c0e130d0bb92fc618bd754bfcdead2a0bdafc136dad4d83481c',
			trackedAtEnd:
				'RECEIVED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED TO_REMOTE:IRREVOCABLY_RESOLVED TO_LOCAL:SPEND_CONFIRMED',
			rowsAtEnd:
				'7e246cfdbe9f1d40534d4f80741d7b80bf2080988783933b0d08dd5b706fb802',
			resolved: true
		},
		monitorRowsStored: 373,
		monitorRows:
			'edc37e5b63233d7d0b655568867e7e33d4b2ddd352e6d7402db29fb59e521b10',
		height: 447
	},
	'static_remotekey:current:bob': {
		alice: {
			published: 29,
			bytes: '9bd753cb324df5156ca288f437e0cc7d289b8db05ec67e1027ec9a969f3efd7e',
			refused: 26,
			refusals:
				'fec73d300cb4d8b0d40947ea0965d4bbc0c655629ed09890a5358c8411f565db',
			trackedAtClose:
				'OFFERED_HTLC:CONFIRMED RECEIVED_HTLC:SPEND_CONFIRMED RECEIVED_HTLC:CONFIRMED OFFERED_HTLC:CONFIRMED TO_LOCAL:CONFIRMED TO_REMOTE:SPEND_CONFIRMED',
			rowsAtClose:
				'1fc51b51a965310a590bfda80d6a0f21b3d2e679e6d5fef23359c66c98bf96d7',
			trackedAtEnd:
				'OFFERED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED TO_LOCAL:SPEND_CONFIRMED TO_REMOTE:IRREVOCABLY_RESOLVED',
			rowsAtEnd:
				'638b18b2128c3fe23b45cdf7dcba13d59d5b2b5cc8557c6a293bc9d4f5c8efb6',
			resolved: true
		},
		bob: {
			published: 44,
			bytes: 'ba2e45b92a8bad2147e8f8a01731ee6c715e1f4b816e0d43a18089158972b04e',
			refused: 38,
			refusals:
				'c263433b63bc33f70b18763b6ac4d8cddc0c94694e8f354689630d9c9549b507',
			trackedAtClose:
				'RECEIVED_HTLC:CONFIRMED OFFERED_HTLC:SPEND_CONFIRMED OFFERED_HTLC:CONFIRMED RECEIVED_HTLC:SPEND_BROADCAST TO_LOCAL:CONFIRMED TO_REMOTE:SPEND_CONFIRMED',
			rowsAtClose:
				'3c31f3dbf6de68d9068e14c15f9f064173d630194b93a0444064e0198d55e5be',
			trackedAtEnd:
				'RECEIVED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED TO_LOCAL:IRREVOCABLY_RESOLVED TO_REMOTE:IRREVOCABLY_RESOLVED TO_LOCAL:IRREVOCABLY_RESOLVED TO_LOCAL:IRREVOCABLY_RESOLVED',
			rowsAtEnd:
				'c1b9ad66c624544ca88e2c1eba4834955143e94f5b910baf3d00b58d0583dcab',
			resolved: true
		},
		monitorRowsStored: 373,
		monitorRows:
			'84bf637c7987b234a2781460d88e280665167fb0045e01fe3c430ed8e9a44e94',
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
			bytes: '1c3c541abd20d4091334ad2efe3701f933c67a2e043cbcc2f57308a8f9686b85',
			refused: 38,
			refusals:
				'7788fcab85316ab8a7b951dbae65bc9babb7dc4f55df0b787cd050a5b225430a',
			trackedAtClose:
				'OFFERED_HTLC:CONFIRMED OFFERED_HTLC:CONFIRMED RECEIVED_HTLC:CONFIRMED RECEIVED_HTLC:CONFIRMED OFFERED_HTLC:CONFIRMED TO_REMOTE:CONFIRMED TO_LOCAL:CONFIRMED',
			rowsAtClose:
				'de4fb8b5b5ca059cfc46dc5cb090ae437541032797c6ab1b4a0d1b4373da8e0f',
			trackedAtEnd:
				'OFFERED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED TO_REMOTE:IRREVOCABLY_RESOLVED TO_LOCAL:IRREVOCABLY_RESOLVED TO_LOCAL:IRREVOCABLY_RESOLVED TO_LOCAL:CONFIRMED TO_LOCAL:IRREVOCABLY_RESOLVED',
			rowsAtEnd:
				'42c2da923052a8d17eea41a2e15119d967d0f4111d4c3ec749c29dcdc94373c4',
			resolved: false
		},
		bob: {
			published: 4,
			bytes: 'c6133b4dfba29546d11fc846ed79b0d54d3cc80b58dbe9dab82a7071e99564d5',
			refused: 0,
			refusals:
				'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
			trackedAtClose:
				'RECEIVED_HTLC:CONFIRMED RECEIVED_HTLC:CONFIRMED OFFERED_HTLC:CONFIRMED OFFERED_HTLC:CONFIRMED RECEIVED_HTLC:CONFIRMED TO_REMOTE:CONFIRMED TO_LOCAL:CONFIRMED',
			rowsAtClose:
				'63f8c180a3e23c28a848280a9c9351e8d22bc0c39bde7aa13a54aa15ab0b4a9f',
			trackedAtEnd:
				'RECEIVED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED TO_REMOTE:IRREVOCABLY_RESOLVED TO_LOCAL:SPEND_CONFIRMED',
			rowsAtEnd:
				'556ebf18c33ee51e118d7a343a0d33cc84c3168ef4a75836288c45cdeabfd43a',
			resolved: true
		},
		monitorRowsStored: 378,
		monitorRows:
			'5e9002d87b2c993584ffd26c7c8276b226916a88049a076b59cc8183ccfdcb35',
		height: 447
	},
	'anchors:current:bob': {
		alice: {
			published: 4,
			bytes: '0f1c117e62c3984cc4b9213cd4a504a534d3be4cb21fd5456abdec4db0c1eda9',
			refused: 0,
			refusals:
				'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
			trackedAtClose:
				'OFFERED_HTLC:CONFIRMED OFFERED_HTLC:CONFIRMED RECEIVED_HTLC:CONFIRMED RECEIVED_HTLC:CONFIRMED OFFERED_HTLC:CONFIRMED TO_LOCAL:CONFIRMED TO_REMOTE:CONFIRMED',
			rowsAtClose:
				'a61613a328bf4c13c230ba767bc6233769e1163b39d84eb23086213d701ceb35',
			trackedAtEnd:
				'OFFERED_HTLC:CONFIRMED OFFERED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED TO_LOCAL:IRREVOCABLY_RESOLVED TO_REMOTE:IRREVOCABLY_RESOLVED',
			rowsAtEnd:
				'0e7c8e7d9c9cdd8ad162e7c6779aac101cc6a14bd8a08d5587f67715d778e882',
			resolved: false
		},
		bob: {
			published: 45,
			bytes: 'd60d0768309cebcd6beee5bdaaf256129a4d97ea9a0b17bd56a14dfc7c36c980',
			refused: 38,
			refusals:
				'60de5af22beb2435e31f0158b495be44a3edeb63c6bf37f1192aa26aaf8773d0',
			trackedAtClose:
				'RECEIVED_HTLC:CONFIRMED RECEIVED_HTLC:CONFIRMED OFFERED_HTLC:CONFIRMED OFFERED_HTLC:CONFIRMED RECEIVED_HTLC:CONFIRMED TO_LOCAL:CONFIRMED TO_REMOTE:CONFIRMED',
			rowsAtClose:
				'c3f57a56e2ef9a5631a1aa0a8da6b263791825c0bd9ceafc1dcb5eb34eff13f7',
			trackedAtEnd:
				'RECEIVED_HTLC:CONFIRMED RECEIVED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED TO_LOCAL:IRREVOCABLY_RESOLVED TO_REMOTE:IRREVOCABLY_RESOLVED TO_LOCAL:IRREVOCABLY_RESOLVED TO_LOCAL:IRREVOCABLY_RESOLVED',
			rowsAtEnd:
				'd6caf1cb6d3050e29b1acf3549e1c2307824cbe12beeea0b423402abc3fba6c7',
			resolved: false
		},
		monitorRowsStored: 391,
		monitorRows:
			'6caf6b747dfdeab02bddcc9d18e4ba75ea353dce647de74a0904f9e902d4436a',
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
			bytes: '8234a2ea21132e2eef5e9ee32b0a52d60b005c046d483a03b5b0ccf3e0e12353',
			refused: 14,
			refusals:
				'749595bf4a00ef911c46689226708393b115c34acb82f844ededbbf32425d670',
			trackedAtClose:
				'RECEIVED_HTLC:SPEND_CONFIRMED RECEIVED_HTLC:SPEND_CONFIRMED OFFERED_HTLC:SPEND_CONFIRMED OFFERED_HTLC:SPEND_CONFIRMED RECEIVED_HTLC:SPEND_CONFIRMED TO_REMOTE:CONFIRMED TO_LOCAL:SPEND_CONFIRMED',
			rowsAtClose:
				'2920c602db330a618faaed7f0a159dcc6c23cf3f0a0c853340fed5905bd308ed',
			trackedAtEnd:
				'RECEIVED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED TO_REMOTE:IRREVOCABLY_RESOLVED TO_LOCAL:IRREVOCABLY_RESOLVED',
			rowsAtEnd:
				'874af96ef54be403e49d01fa63cd2bd6caab7bcd0016e78595d433abfba7f63c',
			resolved: true
		},
		monitorRowsStored: 350,
		monitorRows:
			'f0eded43406bdac3b483b9ed0ba542343c240bcd5026c2bc69cde5a87213d6f5',
		height: 447
	},
	'anchors:revoked:bob': {
		alice: {
			published: 19,
			bytes: '38a3f31e29dfdfe93d5c1b9369226f01b5d7c421d6ba611add0e1c73464f0a09',
			refused: 14,
			refusals:
				'907aec902605de4d5b29fef1b68952dda2f7b60036163b3104da92d21fdf2606',
			trackedAtClose:
				'OFFERED_HTLC:SPEND_CONFIRMED OFFERED_HTLC:SPEND_CONFIRMED RECEIVED_HTLC:SPEND_CONFIRMED RECEIVED_HTLC:SPEND_CONFIRMED OFFERED_HTLC:SPEND_CONFIRMED TO_LOCAL:SPEND_CONFIRMED TO_REMOTE:CONFIRMED',
			rowsAtClose:
				'971e02f880e179dd581e633f04ca7010811ff6bb9d51bd9f0f0db6b93032879d',
			trackedAtEnd:
				'OFFERED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED TO_LOCAL:IRREVOCABLY_RESOLVED TO_REMOTE:IRREVOCABLY_RESOLVED',
			rowsAtEnd:
				'77af16a83ed5d3fc60363067f36c3e7ff2acfffda18d9f103d34f6d21a96bda6',
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
			'ced32f558cc09128672aefa3ca7b1c2d9e277d599f605254b6f856c8cf91649e',
		height: 447
	},
	'taproot:current:alice': {
		alice: {
			published: 46,
			bytes: '5610154341f3417711305a02d94c8a1b5dfd064650b591b955bee40139011bf8',
			refused: 38,
			refusals:
				'76aac8483c393cb4e5a22d16b88c04671fbfc7c273c7efc5da155b53f2cce60e',
			trackedAtClose:
				'OFFERED_HTLC:CONFIRMED OFFERED_HTLC:CONFIRMED RECEIVED_HTLC:CONFIRMED RECEIVED_HTLC:CONFIRMED OFFERED_HTLC:CONFIRMED TO_REMOTE:CONFIRMED TO_LOCAL:CONFIRMED',
			rowsAtClose:
				'315730c0fc88abf9b5e69a61d2eaf7079881846d8fe4d842ea04e9a296166b39',
			trackedAtEnd:
				'OFFERED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED TO_REMOTE:IRREVOCABLY_RESOLVED TO_LOCAL:IRREVOCABLY_RESOLVED TO_LOCAL:IRREVOCABLY_RESOLVED TO_LOCAL:CONFIRMED TO_LOCAL:IRREVOCABLY_RESOLVED',
			rowsAtEnd:
				'894cc06cacc7aabad63c6816af4203e05564dd5338e1c33fdeb2af3f527a979c',
			resolved: false
		},
		bob: {
			published: 4,
			bytes: '4ed68c103b8177938bec79ea713b2293df012b7979374d1f98918de02e8861c2',
			refused: 0,
			refusals:
				'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
			trackedAtClose:
				'RECEIVED_HTLC:CONFIRMED RECEIVED_HTLC:CONFIRMED OFFERED_HTLC:CONFIRMED OFFERED_HTLC:CONFIRMED RECEIVED_HTLC:CONFIRMED TO_REMOTE:CONFIRMED TO_LOCAL:CONFIRMED',
			rowsAtClose:
				'de5812d6e8c9fa0fb7463d43c7eacfb17dc7fc6105eebf5ba7ffd8269b3d9b94',
			trackedAtEnd:
				'RECEIVED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED TO_REMOTE:IRREVOCABLY_RESOLVED TO_LOCAL:SPEND_CONFIRMED',
			rowsAtEnd:
				'af7c3332e9c821c841d08c876699b1a04556af6328e0fee49271003440ae2d9d',
			resolved: true
		},
		monitorRowsStored: 378,
		monitorRows:
			'3e7326e1c719767658a70d08a7d2cc8d7895233d8a70f1ca4132109927518fcb',
		height: 447
	},
	'taproot:current:bob': {
		alice: {
			published: 4,
			bytes: '42763f350d0a7a95446122ee7ac5a09a039b837badcd9215d0211a15e4d691d4',
			refused: 0,
			refusals:
				'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
			trackedAtClose:
				'OFFERED_HTLC:CONFIRMED OFFERED_HTLC:CONFIRMED RECEIVED_HTLC:CONFIRMED RECEIVED_HTLC:CONFIRMED OFFERED_HTLC:CONFIRMED TO_LOCAL:CONFIRMED TO_REMOTE:CONFIRMED',
			rowsAtClose:
				'84e39c1a11624392f282848f228a4b537a2a8cdef1cb4b5cfae7973f1d7807d9',
			trackedAtEnd:
				'OFFERED_HTLC:CONFIRMED OFFERED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED TO_LOCAL:IRREVOCABLY_RESOLVED TO_REMOTE:IRREVOCABLY_RESOLVED',
			rowsAtEnd:
				'a4872ddcfb952fee7ac2d36700c577e073433639efbbd0b7e04a52fde67a9cb6',
			resolved: false
		},
		bob: {
			published: 45,
			bytes: '29ae3dae2bc012679bab37dc2b9d3f3c14eabd0c41793d5a2d1f96d7efd40a18',
			refused: 38,
			refusals:
				'573cf8b5a02608b29edf19b57499dbfd6c58d81bdd14fbd3c6422960385e9ef8',
			trackedAtClose:
				'RECEIVED_HTLC:CONFIRMED RECEIVED_HTLC:CONFIRMED OFFERED_HTLC:CONFIRMED OFFERED_HTLC:CONFIRMED RECEIVED_HTLC:CONFIRMED TO_LOCAL:CONFIRMED TO_REMOTE:CONFIRMED',
			rowsAtClose:
				'3a22f23d6f268705ac6869d91e1eff48762f9457b9b5a72667681e766c1c5e2c',
			trackedAtEnd:
				'RECEIVED_HTLC:CONFIRMED RECEIVED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED TO_LOCAL:IRREVOCABLY_RESOLVED TO_REMOTE:IRREVOCABLY_RESOLVED TO_LOCAL:IRREVOCABLY_RESOLVED TO_LOCAL:IRREVOCABLY_RESOLVED',
			rowsAtEnd:
				'41ef311c46fa1dda344fae3da47bda23724a5aeac8da3548ed6d0aff310f9e32',
			resolved: false
		},
		monitorRowsStored: 391,
		monitorRows:
			'f1b8decb9edbd9abd9fd28bda1125d819a1bfccedd0f5e3690471c0f3cc58835',
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
			bytes: '8ebb7fa27f888e0feee649355cdcca4be73a55b02159647d27a4055da03cd916',
			refused: 14,
			refusals:
				'a9c2794d5c7ba2bb9520c9b05c3fdb40b924cbc9fba365930adcc68d8d44e97e',
			trackedAtClose:
				'RECEIVED_HTLC:SPEND_CONFIRMED RECEIVED_HTLC:SPEND_CONFIRMED OFFERED_HTLC:SPEND_CONFIRMED OFFERED_HTLC:SPEND_CONFIRMED RECEIVED_HTLC:SPEND_CONFIRMED TO_REMOTE:CONFIRMED TO_LOCAL:SPEND_CONFIRMED',
			rowsAtClose:
				'a332c1a4642e67ab869abc03850a9b3c77dda3e03426be32f11816883ed0cde8',
			trackedAtEnd:
				'RECEIVED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED TO_REMOTE:IRREVOCABLY_RESOLVED TO_LOCAL:IRREVOCABLY_RESOLVED',
			rowsAtEnd:
				'd8492e98db2de125ede4acb525d6bc6ecada80f2cfd2a1eee4fee555c041c577',
			resolved: true
		},
		monitorRowsStored: 350,
		monitorRows:
			'bd32efdb5134ecc29b7c08d3d0d41a99012762e9676854cec575fd731e92b246',
		height: 447
	},
	'taproot:revoked:bob': {
		alice: {
			published: 19,
			bytes: '3c55620b4d08acb5e7d6b72905fd47aa0788b7aeab162911754edda0ec547241',
			refused: 14,
			refusals:
				'cc62e65592a64e8000ef7bae9693121d6720f47de1c94b3c4131d8ccd1b85b78',
			trackedAtClose:
				'OFFERED_HTLC:SPEND_CONFIRMED OFFERED_HTLC:SPEND_CONFIRMED RECEIVED_HTLC:SPEND_CONFIRMED RECEIVED_HTLC:SPEND_CONFIRMED OFFERED_HTLC:SPEND_CONFIRMED TO_LOCAL:SPEND_CONFIRMED TO_REMOTE:CONFIRMED',
			rowsAtClose:
				'2a9b5538377a45df1179ad55291671c01719e8f26eb892e551d1964b0d127ef2',
			trackedAtEnd:
				'OFFERED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED RECEIVED_HTLC:IRREVOCABLY_RESOLVED OFFERED_HTLC:IRREVOCABLY_RESOLVED TO_LOCAL:IRREVOCABLY_RESOLVED TO_REMOTE:IRREVOCABLY_RESOLVED',
			rowsAtEnd:
				'0ee1c671dbc2b14fde879e40f0efd277b83cd7c5a55bdf2c6a0d8bdd7c2463de',
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
			'c04bf50ebae6d03f7a07287b9ba79521b177ad2888ea312c8de43644410dcfc7',
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
