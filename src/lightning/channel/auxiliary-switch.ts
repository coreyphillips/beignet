/**
 * Whether this build opens and accepts asset channels (issue #2093).
 *
 * On since an asset channel can also be closed and defended on chain: it
 * is closed cooperatively, swept after a force close, and a revoked
 * commitment of it is punished, HTLC outputs included. With this off an
 * asset opening is refused in both directions, by the channel manager,
 * before a key is derived or a message sent; every other channel is as it
 * was. Tests turn it off to reach that refusal; nothing else may, and the
 * package does not export it. A node without a provider opens and accepts
 * no asset channel whatever this says.
 */
export const auxiliaryChannelOpens = { enabled: true };
