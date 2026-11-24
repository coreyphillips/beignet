export * from './funding';
export * from './commitment';
export * from './htlc';
export * from './revocation';
export * from './anchor';

// What a provider of asset channels builds the asset side of a commitment
// and of a second-level HTLC transaction with (issue #2093). The opening also commits to the two
// payout scripts and the anchor in each holder view.
export {
	buildTaprootToLocalOutput,
	buildTaprootToRemoteOutput,
	buildTaprootAnchorOutput,
	buildTaprootOfferedHtlcOutput,
	buildTaprootReceivedHtlcOutput,
	buildTaprootSecondLevelOutput
} from './commitment-taproot';
export type {
	ITaprootAuxLeaf,
	ITaprootCommitOutput,
	ITaprootHtlcOutput,
	ITaprootLeafSpend,
	TaprootOutputFormat
} from './commitment-taproot';
export { createTaprootFundingScript } from './funding-taproot';
export type { ITaprootFundingScript } from './funding-taproot';
