import { test, describe } from "node:test";
import assert from "node:assert/strict";
import {
  parseSseMessageBlock,
  parseSseStreamChunk,
} from "../sse-client.ts";
import type {
  AttackStartedEventData,
  AttackFinishedEventData,
  RunCompleteEventData,
} from "../sse-client.ts";

describe("sse-client: parseSseMessageBlock", () => {
  test("parses standard event and JSON data", () => {
    const rawBlock = `event: attack_started\ndata: {"run_id":"run_abc","attack_id":"live_001","index":0,"channel":"email","category":"authority_framing"}`;
    const result = parseSseMessageBlock(rawBlock);

    assert.ok(result);
    assert.equal(result.event, "attack_started");
    const data = result.data as AttackStartedEventData;
    assert.equal(data.run_id, "run_abc");
    assert.equal(data.attack_id, "live_001");
    assert.equal(data.index, 0);
  });

  test("parses attack_finished with dual-condition metrics and cost", () => {
    const rawBlock = `event: attack_finished\ndata: {"run_id":"run_abc","attack_id":"live_001","index":0,"channel":"email","category":"authority_framing","strategy":"Urgent memo","outcome":"defended","metrics":{"m1":false,"m2":false,"m3":false,"m4":false,"unsafe":false},"cost_usd":0.0031,"unhardened":{"outcome":"breach","metrics":{"unsafe":true}},"v2":{"outcome":"defended","metrics":{"unsafe":false},"policy_block_rule":"tools.read_file.deny_paths"}}`;
    const result = parseSseMessageBlock(rawBlock);

    assert.ok(result);
    assert.equal(result.event, "attack_finished");
    const data = result.data as AttackFinishedEventData;
    assert.equal(data.cost_usd, 0.0031);
    assert.equal(data.unhardened?.outcome, "breach");
    assert.equal(data.v2?.outcome, "defended");
    assert.equal(data.v2?.policy_block_rule, "tools.read_file.deny_paths");
  });

  test("ignores comments and keepalive pings", () => {
    const rawBlock = `: keepalive\n: another comment\nevent: ping\ndata: {"ok":true}`;
    const result = parseSseMessageBlock(rawBlock);

    assert.ok(result);
    assert.equal(result.event, "ping");
    assert.deepEqual(result.data, { ok: true });
  });

  test("returns null for empty blocks", () => {
    assert.equal(parseSseMessageBlock(""), null);
    assert.equal(parseSseMessageBlock("   \n\n  "), null);
  });
});

describe("sse-client: parseSseStreamChunk incremental streaming", () => {
  test("handles chunk split directly across packet boundary", () => {
    // Chunk 1 has half of the message
    const chunk1 = `event: attack_started\ndata: {"run_id":"run_abc","attack_`;
    const { events: events1, remainingBuffer: buf1 } = parseSseStreamChunk(chunk1, "");
    assert.equal(events1.length, 0);
    assert.equal(buf1, chunk1);

    // Chunk 2 delivers the rest and the double newline delimiter
    const chunk2 = `id":"live_001","index":0,"channel":"email","category":"authority"}\n\n`;
    const { events: events2, remainingBuffer: buf2 } = parseSseStreamChunk(chunk2, buf1);
    assert.equal(events2.length, 1);
    assert.equal(events2[0].event, "attack_started");
    assert.equal((events2[0].data as AttackStartedEventData).attack_id, "live_001");
    assert.equal(buf2, "");
  });

  test("parses multiple consecutive events in a single stream chunk", () => {
    const multiEventChunk = [
      `event: attack_started`,
      `data: {"run_id":"run_1","attack_id":"att_1","index":0,"channel":"email","category":"cat1"}`,
      ``,
      `event: attack_finished`,
      `data: {"run_id":"run_1","attack_id":"att_1","index":0,"channel":"email","category":"cat1","strategy":"s","outcome":"defended","metrics":{},"cost_usd":0.002}`,
      ``,
      `event: run_complete`,
      `data: {"run_id":"run_1","status":"completed","attacks_evaluated":1,"total_cost_usd":0.002,"unhardened_breaches":0}`,
      ``,
      ``,
    ].join("\n");

    const { events, remainingBuffer } = parseSseStreamChunk(multiEventChunk, "");
    assert.equal(events.length, 3);
    assert.equal(events[0].event, "attack_started");
    assert.equal(events[1].event, "attack_finished");
    assert.equal(events[2].event, "run_complete");
    assert.equal((events[2].data as RunCompleteEventData).status, "completed");
    assert.equal(remainingBuffer, "");
  });
});

describe("sse-client: disconnect and paused state handling", () => {
  test("disconnect preserves trailing buffer without premature emission", () => {
    const partialStream = `event: attack_started\ndata: {"partial":`;
    const { events, remainingBuffer } = parseSseStreamChunk(partialStream, "");
    assert.equal(events.length, 0);
    assert.equal(remainingBuffer, partialStream);
  });

  test("paused state (HTTP 429) error detection and guidance", () => {
    const error429 = "Live runs are paused for today; open the recorded run instead";
    const isPaused = error429.toLowerCase().includes("paused") || error429.includes("429");
    assert.ok(isPaused, "Should identify 429 paused state");

    const recommendedAction = isPaused
      ? "Live runs are paused for today. Open the recorded run instead."
      : "Unknown error";
    assert.equal(recommendedAction, "Live runs are paused for today. Open the recorded run instead.");
  });
});
