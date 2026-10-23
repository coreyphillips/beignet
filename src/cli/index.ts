/**
 * `beignet/node` and `beignet/daemon` together, as this entry exported them
 * before they were split, kept for existing imports. Loading it loads the
 * daemon; import `beignet/node` for the node alone.
 * @module beignet/cli
 */
export * from '../node';
export * from '../daemon';
