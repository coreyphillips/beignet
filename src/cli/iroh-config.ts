import { validateIrohRelayUrl } from '../lightning/transport/iroh';

export interface IrohDaemonConfig {
	/** Experimental phone link. Peers and relays can see your IP address. */
	iroh?: boolean;
	/** Custom relays replace the public defaults. Empty disables relays. */
	irohRelays?: string[];
	/** Public endpoint discovery and publication (default true when enabled). */
	irohDiscovery?: boolean;
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
	for (const name of ['iroh', 'irohDiscovery'] as const) {
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
}
