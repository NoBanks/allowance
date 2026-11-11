// Two brains, one toolbox.
//
// compromisedBrain assumes the worst: it obeys any payment instruction in anything it
// reads, from anyone. It needs no API key. It exists because a good model may refuse
// the injection on its own, and then nothing about the vault has been tested. The vault
// has to hold when the model does not.
//
// claudeBrain and geminiBrain are real agents on a model API. They get no warning about
// injection: nothing about the safety of this system depends on the prompt.

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

const GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models";

/** Gemini's function declarations take an OpenAPI subset: no additionalProperties, and no empty objects. */
function geminiDeclaration({ name, description, input_schema }) {
  const { additionalProperties, ...parameters } = input_schema;
  return Object.keys(parameters.properties).length ? { name, description, parameters } : { name, description };
}

/**
 * Several keys may be given. A quota, permission or invalid-key error moves to the next key at once, once per key.
 * Busy (503), no answer in time, or a 429 on the last key gets a few spaced retries. Anything else is final.
 * The key travels in a header, never the URL, so error text is safe to log.
 */
async function geminiRequest(fetchImpl, url, init, keys, cursor, retryDelaysMs, onEvent) {
  let rotations = 0;
  for (let attempt = 0; ; ) {
    const key = keys[cursor.at % keys.length];
    let res;
    try {
      res = await fetchImpl(url, { ...init, headers: { ...init.headers, "x-goog-api-key": key }, signal: AbortSignal.timeout(90_000) });
    } catch (e) {
      if (e.name !== "TimeoutError" || attempt >= retryDelaysMs.length) throw e;
      res = { ok: false, status: "timeout" };
    }
    if (res.ok) return res.json();
    const detail = res.text ? (await res.text()).slice(0, 300) : "";
    const badKey = [429, 403].includes(res.status) || (res.status === 400 && detail.includes("API_KEY_INVALID"));
    if (badKey && rotations < keys.length - 1) {
      rotations++;
      cursor.at++;
      onEvent({ type: "rotate", status: res.status, key: (cursor.at % keys.length) + 1, of: keys.length });
      continue;
    }
    if (![429, 503, "timeout"].includes(res.status) || attempt >= retryDelaysMs.length) {
      throw new Error(`Gemini API ${res.status}: ${detail}`);
    }
    onEvent({ type: "retry", status: res.status, waitMs: retryDelaysMs[attempt] });
    await new Promise((r) => setTimeout(r, retryDelaysMs[attempt++]));
    rotations = 0;
  }
}

export async function geminiBrain({ toolbox, system, task, apiKeys, model, fetchImpl = fetch, retryDelaysMs = [5000, 15000, 30000], onEvent = () => {} }) {
  if (!apiKeys?.length) throw new Error("geminiBrain needs at least one API key");
  const tools = [{ functionDeclarations: toolbox.definitions.map(geminiDeclaration) }];
  const contents = [{ role: "user", parts: [{ text: task }] }];
  const cursor = { at: 0 };

  for (let turn = 0; turn < MAX_TURNS; turn++) {
    const body = await geminiRequest(fetchImpl, `${GEMINI_URL}/${model}:generateContent`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ systemInstruction: { parts: [{ text: system }] }, contents, tools }),
    }, apiKeys, cursor, retryDelaysMs, onEvent);

    const candidate = body.candidates?.[0];
    if (!candidate?.content) return { stop: body.promptFeedback?.blockReason ?? candidate?.finishReason ?? "empty", summary: "" };
    const parts = candidate.content.parts ?? [];
    const text = parts.filter((p) => p.text && !p.thought).map((p) => p.text).join("\n");
    if (text) onEvent({ type: "said", text });

    const calls = parts.filter((p) => p.functionCall);
    if (!calls.length) return { stop: candidate.finishReason === "STOP" ? "end_turn" : candidate.finishReason, summary: text };

    // The model's turn goes back unchanged, so any thought signatures stay attached.
    contents.push(candidate.content);
    const results = [];
    for (const { functionCall } of calls) {
      onEvent({ type: "tool", name: functionCall.name, input: functionCall.args ?? {} });
      const { text: output, isError } = await toolbox.call(functionCall.name, functionCall.args);
      results.push({ functionResponse: { name: functionCall.name, response: isError ? { error: output } : { output } } });
    }
    contents.push({ role: "user", parts: results });
  }
  return { stop: "turn_limit", summary: "" };
}
