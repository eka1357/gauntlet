/**
 * Server-Sent Events (SSE) parsing utilities and stream handler for Gauntlet live runs.
 */

export interface SseEvent<T = unknown> {
  event: string;
  data: T;
}

export interface AttackStartedEventData {
  run_id: string;
  attack_id: string;
  index: number;
  channel: string;
  category: string;
}

export interface AttackFinishedEventData {
  run_id: string;
  attack_id: string;
  index: number;
  channel: string;
  category: string;
  strategy: string;
  outcome: "defended" | "breach";
  metrics: {
    m1?: boolean;
    m2?: boolean;
    m3?: boolean;
    m4?: boolean;
    unsafe?: boolean;
  };
  policy_block_rule?: string | null;
  cost_usd: number;
  unhardened?: {
    outcome: "defended" | "breach";
    metrics: Record<string, boolean>;
    policy_block_rule?: string | null;
  };
  v2?: {
    outcome: "defended" | "breach";
    metrics: Record<string, boolean>;
    policy_block_rule?: string | null;
  };
}

export interface RunCompleteEventData {
  run_id: string;
  status: "completed" | "budget_capped" | "error";
  attacks_evaluated: number;
  budget_capped?: boolean;
  budget_cap_usd?: number;
  total_cost_usd: number;
  unhardened_breaches: number;
  unhardened_unsafe?: number;
  v2_breaches?: number;
  v2_unsafe?: number;
  target_mode?: string;
}

export interface RunErrorEventData {
  run_id: string;
  error: string;
}

/**
 * Parses a single SSE message block separated by empty lines.
 */
export function parseSseMessageBlock(block: string): SseEvent | null {
  const lines = block.split(/\r?\n/);
  let eventName = "message";
  const dataLines: string[] = [];

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line || line.startsWith(":")) continue; // ignore comments or blank lines
    if (line.startsWith("event:")) {
      eventName = line.slice(6).trim();
    } else if (line.startsWith("data:")) {
      dataLines.push(line.slice(5).trim());
    }
  }

  if (dataLines.length === 0) return null;

  const rawData = dataLines.join("\n");
  try {
    const parsedData = JSON.parse(rawData);
    return { event: eventName, data: parsedData };
  } catch {
    return { event: eventName, data: rawData };
  }
}

/**
 * Incrementally processes incoming text chunks from an SSE HTTP stream.
 */
export function parseSseStreamChunk(
  chunk: string,
  buffer: string = ""
): { events: SseEvent[]; remainingBuffer: string } {
  const fullText = buffer + chunk;
  const blocks = fullText.split(/\r?\n\r?\n/);
  const remainingBuffer = blocks.pop() ?? "";
  const events: SseEvent[] = [];

  for (const b of blocks) {
    const trimmed = b.trim();
    if (trimmed) {
      const parsed = parseSseMessageBlock(trimmed);
      if (parsed) {
        events.push(parsed);
      }
    }
  }

  return { events, remainingBuffer };
}
