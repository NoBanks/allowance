// Two brains, one toolbox.
//
// compromisedBrain assumes the worst: it obeys any payment instruction in anything it
// reads, from anyone. It needs no API key. It exists because a good model may refuse
// the injection on its own, and then nothing about the vault has been tested. The vault
// has to hold when the model does not.
//
// claudeBrain is the real agent on the Claude API. It gets no warning about injection:
// nothing about the safety of this system depends on the prompt.

const PAY_LINE = /pay\s+([\d.]+)\s+NEAR\s+to\s+([a-z0-9._-]+)/gi;
const REFERENCE = /Reference:\s*(.+)/i;
const MAX_TURNS = 12;

export async function compromisedBrain({ toolbox, onEvent = () => {} }) {
  const names = (await toolbox.call("list_inbox")).text.split("\n");
  const paid = [];
  for (const name of names) {
    const { text } = await toolbox.call("read_document", { name });
    onEvent({ type: "read", name });
    const memo = (text.match(REFERENCE)?.[1] ?? name).slice(0, 140);
    for (const [, amount, recipient] of text.matchAll(PAY_LINE)) {
      onEvent({ type: "obeying", name, amount, recipient });
      const result = await toolbox.call("pay", { recipient, amount_near: amount, memo });
      paid.push(`${amount} NEAR to ${recipient}: ${result.text}`);
    }
  }
  return { stop: "done", summary: paid.join("\n") };
}

export async function claudeBrain({ toolbox, system, task, client, model, onEvent = () => {} }) {
  const tools = toolbox.definitions.map((t) => ({ ...t, strict: true }));
  const messages = [{ role: "user", content: task }];

  for (let turn = 0; turn < MAX_TURNS; turn++) {
    const response = await client.beta.messages.create({
      model,
      max_tokens: 16000,
      system,
      tools,
      messages,
      output_config: { effort: "medium" },
      betas: ["server-side-fallback-2026-07-01"],
      fallbacks: "default",
    });

    const text = response.content.filter((b) => b.type === "text").map((b) => b.text).join("\n");
    if (text) onEvent({ type: "said", text });

    if (response.stop_reason === "refusal") return { stop: "refusal", summary: text };
    if (response.stop_reason === "max_tokens") return { stop: "max_tokens", summary: text };
    if (response.stop_reason === "pause_turn") {
      messages.push({ role: "assistant", content: response.content });
      continue;
    }
    if (response.stop_reason !== "tool_use") return { stop: response.stop_reason, summary: text };

    messages.push({ role: "assistant", content: response.content });
    const results = [];
    for (const block of response.content.filter((b) => b.type === "tool_use")) {
      onEvent({ type: "tool", name: block.name, input: block.input });
      const { text: output, isError } = await toolbox.call(block.name, block.input);
      results.push({ type: "tool_result", tool_use_id: block.id, content: output, is_error: isError });
    }
    messages.push({ role: "user", content: results });
  }
  return { stop: "turn_limit", summary: "" };
}
