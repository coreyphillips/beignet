import { validateIrohRelayUrl } from '../lightning/transport/iroh';

export interface IrohDaemonConfig {
	/** Experimental phone link. Peers and relays can see your IP address. */
	iroh?: boolean;
	/** Custom relays replace the public defaults. Empty disables relays. */
	irohRelays?: string[];
	/** Public endpoint discovery and publication (default true when enabled). */
	irohDiscovery?: boolean;
	/**
	 * Keep every Iroh connection on the relay (default false). No direct path
	 * is offered or taken, so someone who holds the node's Iroh link cannot
	 * learn its IP address; the relay operator still sees it. Slower than a
	 * direct path. Needs a relay, and learned addresses are then dialed
	 * through the SOCKS5 proxy or not at all. With an Iroh binding that
	 * cannot remove its IP transport, the node stops serving Iroh on a
	 * network whose router grants port mappings (see the Iroh section).
	 */
	irohRelayOnly?: boolean;
}

export function irohBooleanEnv(name: string): boolean | undefined {
	const value = process.env[name];
	if (value === undefined) return undefined;
	if (value === 'true') return true;
	if (value === 'false') return false;
	throw new Error(`${name} must be exactly true or false`);
}

export function irohRelaysEnv(): string[] | undefined {
	return process.env.BEIGNET_IROH_RELAYS?.split(',')
		.map((url) => url.trim())
		.filter(Boolean);
}

export function validateIrohConfig(config: IrohDaemonConfig): void {
	for (const name of ['iroh', 'irohDiscovery', 'irohRelayOnly'] as const) {
		if (config[name] !== undefined && typeof config[name] !== 'boolean')
			throw new Error(`${name} must be a boolean`);
	}
	if (config.irohRelays !== undefined) {
		if (
			!Array.isArray(config.irohRelays) ||
			config.irohRelays.some((value) => typeof value !== 'string')
		)
			throw new Error('irohRelays must be an array of relay URLs');
		config.irohRelays.forEach(validateIrohRelayUrl);
	}
	if (config.iroh && config.irohRelayOnly && config.irohRelays?.length === 0)
		throw new Error(
			'irohRelayOnly needs a relay, and an empty irohRelays disables them'
		);
}
