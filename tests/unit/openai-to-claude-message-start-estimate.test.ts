import assert from "node:assert/strict";
import test from "node:test";

import { openaiToClaudeResponse } from "../../open-sse/translator/response/openai-to-claude.ts";

const FIRST_CHUNK = {
  id: "chatcmpl-message-start-estimate",
  model: "deepseek-v4.1-flash",
  choices: [{ index: 0, delta: { content: "OK" }, finish_reason: null }],
};

function messageStartUsage(state: Record<string, unknown>) {
  const events = (openaiToClaudeResponse(FIRST_CHUNK, state) ?? []) as Array<
    Record<string, any>
  >;
  return events.find((event) => event.type === "message_start")?.message.usage;
}

test("message_start carries the request-side input estimate when upstream usage is not known yet", () => {
  const usage = messageStartUsage({ toolCalls: new Map(), estimatedInputTokens: 4200 });
  assert.deepEqual(usage, { input_tokens: 4200, output_tokens: 0 });
});

test("message_start prefers upstream usage already seen on the first chunk", () => {
  const usage = messageStartUsage({
    toolCalls: new Map(),
    estimatedInputTokens: 4200,
    usage: { input_tokens: 3900, output_tokens: 0 },
  });
  assert.deepEqual(usage, { input_tokens: 3900, output_tokens: 0 });
});

test("message_start falls back to zero without any estimate", () => {
  const usage = messageStartUsage({ toolCalls: new Map() });
  assert.deepEqual(usage, { input_tokens: 0, output_tokens: 0 });
});
