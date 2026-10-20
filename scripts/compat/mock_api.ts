// A minimal stand-in for the Anthropic Messages API, so the compatibility check can run the real
// `claude` without a model or an API key. The system under test is Claude Code's handling of a tool
// call (hooks, permission modes, what it reports back), not what a model would say, so the "model"
// is a script: on its first turn it asks for one Bash command, and after the result comes back it says
// "done". It records that result, so the check can see what Claude Code told the model.
import type { ToolResult } from "./lib";

const TOOL_USE_ID = "toolu_compat";

export interface MockApi {
  // Point ANTHROPIC_BASE_URL here.
  url: string;
  // The result Claude Code reported for the scripted call, if it has by now.
  toolResult(): ToolResult | undefined;
  stop(): void;
}

const sse = (events: [string, unknown][]) => events.map(([name, data]) => `event: ${name}\ndata: ${JSON.stringify(data)}\n\n`).join("");

function resultText(content: unknown): string {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  return content.map((b: any) => (typeof b?.text === "string" ? b.text : "")).join("\n");
}

// Answers `command` once to every conversation that offers a Bash tool.
export function startMockApi(command: string): MockApi {
  let result: ToolResult | undefined;

  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    async fetch(req) {
      const path = new URL(req.url).pathname;
      if (path.endsWith("/messages/count_tokens")) return Response.json({ input_tokens: 1 });
      if (!path.endsWith("/v1/messages")) return Response.json({});

      const body: any = await req.json();
      const messages: any[] = Array.isArray(body.messages) ? body.messages : [];
      for (const m of messages) {
        for (const block of Array.isArray(m.content) ? m.content : []) {
          if (block?.type === "tool_result" && block.tool_use_id === TOOL_USE_ID) {
            result = { isError: block.is_error === true, text: resultText(block.content) };
          }
        }
      }

      const offered = (Array.isArray(body.tools) ? body.tools : []).some((t: any) => t?.name === "Bash");
      const content = offered && !result
        ? { type: "tool_use", id: TOOL_USE_ID, name: "Bash", input: { command, description: "Compatibility check" } }
        : { type: "text", text: "done" };
      const stop_reason = content.type === "tool_use" ? "tool_use" : "end_turn";
      const id = `msg_compat_${Math.random().toString(36).slice(2)}`;
      const usage = { input_tokens: 1, output_tokens: 1 };

      if (!body.stream) {
        return Response.json({ id, type: "message", role: "assistant", model: body.model, content: [content], stop_reason, stop_sequence: null, usage });
      }
      const block =
        content.type === "tool_use"
          ? [
              ["content_block_start", { type: "content_block_start", index: 0, content_block: { ...content, input: {} } }],
              ["content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "input_json_delta", partial_json: JSON.stringify(content.input) } }],
            ]
          : [
              ["content_block_start", { type: "content_block_start", index: 0, content_block: { type: "text", text: "" } }],
              ["content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "text_delta", text: content.text } }],
            ];
      const events: [string, unknown][] = [
        ["message_start", { type: "message_start", message: { id, type: "message", role: "assistant", model: body.model, content: [], stop_reason: null, stop_sequence: null, usage } }],
        ...(block as [string, unknown][]),
        ["content_block_stop", { type: "content_block_stop", index: 0 }],
        ["message_delta", { type: "message_delta", delta: { stop_reason, stop_sequence: null }, usage: { output_tokens: 1 } }],
        ["message_stop", { type: "message_stop" }],
      ];
      return new Response(sse(events), { headers: { "content-type": "text/event-stream" } });
    },
  });

  return { url: `http://127.0.0.1:${server.port}`, toolResult: () => result, stop: () => void server.stop(true) };
}
