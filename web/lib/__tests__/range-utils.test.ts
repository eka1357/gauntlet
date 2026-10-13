import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { computeWilsonCi, getAttackSquareState } from "../range-utils.ts";
import type { AttackRecord } from "../api.ts";

describe("range-utils: computeWilsonCi", () => {
  test("computes zero counts with upper bound", () => {
    const [low, high] = computeWilsonCi(0, 190);
    assert.equal(low, 0.0);
    // Upper bound for 0/190 should be approximately 0.0198 (~2.0%)
    assert.ok(high > 0.015 && high < 0.025, `Expected ~0.0198, got ${high}`);
  });

  test("computes realistic baseline breach rate CI (49 of 190)", () => {
    const [low, high] = computeWilsonCi(49, 190);
    // Rate is 49/190 = 0.2579; Wilson CI is approximately [0.20, 0.32]
    assert.ok(low > 0.18 && low < 0.22, `Expected ~0.20, got ${low}`);
    assert.ok(high > 0.30 && high < 0.34, `Expected ~0.32, got ${high}`);
  });

  test("handles n=0 edge case safely", () => {
    const [low, high] = computeWilsonCi(0, 0);
    assert.deepEqual([low, high], [0, 0]);
  });
});

describe("range-utils: getAttackSquareState", () => {
  const mockBaseAttack: AttackRecord = {
    id: "att_001",
    channel: "email",
    category: "authority_framing",
    strategy: "Spoofed customs notice",
    is_probe: false,
    unhardened: {
      outcome: "breach",
      m1: false,
      m2: false,
      m3: true,
      m4: false,
      unsafe: true,
      policy_block_rule: null,
    },
    v1: {
      outcome: "defended",
      m1: false,
      m2: false,
      m3: false,
      m4: false,
      unsafe: false,
      policy_block_rule: "tools.read_file.deny_paths",
    },
    v2: {
      outcome: "defended",
      m1: false,
      m2: false,
      m3: false,
      m4: false,
      unsafe: false,
      policy_block_rule: "tools.read_file.deny_paths",
    },
  };

  test("unhardened state marks unsafe attack as red breach without teal outline", () => {
    const state = getAttackSquareState(mockBaseAttack, "unhardened");
    assert.equal(state.fillColor, "breach");
    assert.equal(state.isUnsafe, true);
    assert.equal(state.hasTealOutline, false);
  });

  test("v2 state for previously unsafe attack stopped by rule receives teal outline and defended fill", () => {
    const state = getAttackSquareState(mockBaseAttack, "v2");
    assert.equal(state.fillColor, "defended");
    assert.equal(state.isUnsafe, false);
    assert.equal(state.hasTealOutline, true);
    assert.equal(state.policyRule, "tools.read_file.deny_paths");
  });

  test("canary-only leak (M4 without unsafe) receives amber in-flight fill", () => {
    const probeAttack: AttackRecord = {
      id: "probe_001",
      channel: "email",
      category: "channel_probe_partner_address",
      strategy: "External partner recipient leak",
      is_probe: true,
      unhardened: {
        outcome: "defended",
        m1: false,
        m2: false,
        m3: false,
        m4: true,
        unsafe: false,
        policy_block_rule: null,
      },
      v1: {
        outcome: "defended",
        m1: false,
        m2: false,
        m3: false,
        m4: true,
        unsafe: false,
        policy_block_rule: null,
      },
      v2: {
        outcome: "defended",
        m1: false,
        m2: false,
        m3: false,
        m4: false,
        unsafe: false,
        policy_block_rule: "tools.send_email.allow_recipients",
      },
    };

    const unhState = getAttackSquareState(probeAttack, "unhardened");
    assert.equal(unhState.fillColor, "in-flight");
    assert.equal(unhState.isCanaryOnly, true);
    assert.equal(unhState.isUnsafe, false);

    const v1State = getAttackSquareState(probeAttack, "v1");
    assert.equal(v1State.fillColor, "in-flight");
    assert.equal(v1State.isCanaryOnly, true);

    const v2State = getAttackSquareState(probeAttack, "v2");
    assert.equal(v2State.fillColor, "defended");
    assert.equal(v2State.isCanaryOnly, false);
  });
});
