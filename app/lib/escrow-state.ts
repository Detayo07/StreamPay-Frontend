import type { Stream } from "@/app/types/openapi";

/** Raw-unit escrow snapshot used by cancellation and withdrawal computations. */
export interface EscrowState {
  total: bigint;
  released: bigint;
  vested: bigint;
}

export type EscrowStateResult =
  | { ok: true; value: EscrowState }
  | { ok: false; code: "ESCROW_UNKNOWN" };

/** Capture the cancellation instant; callers can replace this clock in tests. */
export function escrowNow(): Date {
  return new Date();
}

function parseAmount(value: string | undefined): bigint | null {
  return typeof value === "string" && /^-?\d+$/.test(value)
    ? BigInt(value)
    : null;
}

function parseTime(value: string | undefined): number | null {
  if (!value) return null;
  const time = Date.parse(value);
  return Number.isFinite(time) ? time : null;
}

/**
 * Resolve persisted raw escrow amounts at an injected time. A stream with a
 * vesting window uses exact integer linear vesting; legacy records without a
 * window use their persisted vested snapshot. Unknown data fails closed.
 */
export function resolveEscrowState(stream: Stream, now: Date): EscrowStateResult {
  const totalAmount = parseAmount(stream.totalAmount);
  const releasedAmount = parseAmount(stream.releasedAmount);
  if (totalAmount === null || releasedAmount === null || !Number.isFinite(now.getTime())) {
    return { ok: false, code: "ESCROW_UNKNOWN" };
  }

  let vestedAmount: bigint;
  if (stream.startTime !== undefined || stream.endTime !== undefined) {
    const start = parseTime(stream.startTime);
    const end = parseTime(stream.endTime);
    if (start === null || end === null || end <= start) {
      return { ok: false, code: "ESCROW_UNKNOWN" };
    }
    const pause = stream.pausedAt === undefined ? null : parseTime(stream.pausedAt);
    if (stream.pausedAt !== undefined && pause === null) {
      return { ok: false, code: "ESCROW_UNKNOWN" };
    }
    const pausedDuration = stream.pausedDurationMs ?? 0;
    if (!Number.isSafeInteger(pausedDuration) || pausedDuration < 0) {
      return { ok: false, code: "ESCROW_UNKNOWN" };
    }
    const effectiveNow = pause === null ? now.getTime() : Math.min(now.getTime(), pause);
    const duration = end - start;
    const elapsed = Math.max(0, Math.min(effectiveNow - start - pausedDuration, duration));
    vestedAmount = totalAmount * BigInt(elapsed) / BigInt(duration);
  } else {
    const snapshot = parseAmount(stream.vestedAmount);
    if (snapshot === null) return { ok: false, code: "ESCROW_UNKNOWN" };
    vestedAmount = snapshot;
  }

  return { ok: true, value: { total: totalAmount, released: releasedAmount, vested: vestedAmount } };
}
