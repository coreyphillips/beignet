/**
 * Recovery Protocol (docs/RECOVERY-PROTOCOL.md).
 *
 * Phase 1: the safety transition layer and the durable outbox.
 * Phase 2: the hash-chained recovery journal, full-state snapshots with
 * compaction, and deterministic reconstruction.
 * Capsules, guardians and writer epochs are later phases.
 */

export * from './types';
export * from './recovery-manager';
export * from './frame-codec';
export * from './journal';
