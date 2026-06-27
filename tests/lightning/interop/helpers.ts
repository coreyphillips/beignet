/**
 * Backward-compatibility re-export shim.
 *
 * The original helpers.ts has been refactored into:
 * - shared-helpers.ts (implementation-agnostic utilities)
 * - lnd-helpers.ts (LND-specific helpers)
 *
 * This file re-exports everything from lnd-helpers (which itself
 * re-exports shared-helpers), so existing interop.test.ts imports
 * continue to work unchanged.
 */
export * from './lnd-helpers';
