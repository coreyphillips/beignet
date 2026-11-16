/**
 * Whether this build opens and accepts asset channels (issue #2093).
 *
 * Off until an asset channel can also be closed and defended on chain: a
 * channel that can be opened and cannot be closed cooperatively, swept or
 * punished is not offered to anyone. With this off an asset opening is
 * refused in both directions, by the channel manager, before a key is
 * derived or a message sent; every other channel is as it was. The step
 * that completes the on-chain side turns it on. Tests turn it on to reach
 * the code behind it; nothing else may, and the package does not export it.
 */
export const auxiliaryChannelOpens = { enabled: false };
