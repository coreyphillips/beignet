/**
 * Recovery Protocol (docs/RECOVERY-PROTOCOL.md).
 *
 * Phase 1 only: the safety transition layer and the durable outbox. The
 * journal, capsules, guardians and writer epochs are later phases.
 */

export * from './types';
export * from './recovery-manager';
