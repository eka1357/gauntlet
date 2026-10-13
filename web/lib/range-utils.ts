import type { AttackRecord } from "./api";

export type AttackCondition = "unhardened" | "v1" | "v2";

export type SquareColor = "breach" | "in-flight" | "defended";

export interface SquareVisualState {
  fillColor: SquareColor;
  hasTealOutline: boolean;
  isUnsafe: boolean;
  isCanaryOnly: boolean;
  isDefended: boolean;
  policyRule: string | null;
}

/**
 * Wilson score interval with continuity correction / asymptotic formula.
 * Returns [lower, upper] as fractions in [0, 1].
 */
export function computeWilsonCi(k: number, n: number, z = 1.95996): [number, number] {
  if (n <= 0) return [0, 0];
  const p = Math.max(0, Math.min(1, k / n));
  const z2 = z * z;
  const denom = 1 + z2 / n;
  const center = (p + z2 / (2 * n)) / denom;
  const margin = (z * Math.sqrt((p * (1 - p)) / n + z2 / (4 * n * n))) / denom;

  const low = Math.max(0, center - margin);
  const high = Math.min(1, center + margin);
  return [Number(low.toFixed(4)), Number(high.toFixed(4))];
}

/**
 * Determines the visual state for an attack square under a chosen condition
 * per DESIGN.md:
 * - red = UNSAFE (M1 or M2 or M3)
 * - amber = canary-only leak (M4 without UNSAFE)
 * - grey = defended
 * - teal outline = unsafe when unhardened but stopped by a named policy rule under v1/v2
 */
export function getAttackSquareState(
  attack: AttackRecord,
  condition: AttackCondition
): SquareVisualState {
  const condData = attack[condition];
  const isUnsafe = Boolean(
    condData.unsafe || condData.m1 || condData.m2 || condData.m3
  );
  const isCanaryOnly = Boolean(!isUnsafe && condData.m4);
  const isDefended = !isUnsafe && !isCanaryOnly;

  let fillColor: SquareColor = "defended";
  if (isUnsafe) {
    fillColor = "breach";
  } else if (isCanaryOnly) {
    fillColor = "in-flight";
  }

  // Teal outline rule:
  // Must be under v1 or v2, unsafe when unhardened, not unsafe under current condition,
  // and stopped by a named policy rule
  const wasUnsafeUnhardened = Boolean(
    attack.unhardened.unsafe ||
      attack.unhardened.m1 ||
      attack.unhardened.m2 ||
      attack.unhardened.m3
  );

  const hasTealOutline = Boolean(
    condition !== "unhardened" &&
      wasUnsafeUnhardened &&
      !isUnsafe &&
      condData.policy_block_rule
  );

  return {
    fillColor,
    hasTealOutline,
    isUnsafe,
    isCanaryOnly,
    isDefended,
    policyRule: condData.policy_block_rule,
  };
}
