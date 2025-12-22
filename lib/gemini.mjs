export function maskContents(contents) {
  try {
    if (!Array.isArray(contents)) return '[invalid-contents]';
    const firstText = contents?.[0]?.parts?.[0]?.text;
    if (typeof firstText !== 'string') return '[no-text]';
    const trimmed = firstText.slice(0, 120);
    return `${trimmed}${firstText.length > 120 ? '...' : ''}`;
  } catch {
    return '[mask-error]';
  }
}

export function usageFrom(obj) {
  if (!obj || typeof obj !== 'object') return null;
  const u = obj.usageMetadata;
  if (u && typeof u === 'object') {
    return {
      total: u.totalTokenCount,
      input: u.promptTokenCount,
      output: u.candidatesTokenCount,
      reasoning: u.reasoningTokenCount,
      input_cached: u.cachedPromptTokenCount
    };
  }
  const u2 = obj.usage;
  if (u2 && typeof u2 === 'object') {
    return {
      total: u2.total_tokens,
      input: u2.prompt_tokens,
      output: u2.completion_tokens,
      reasoning: u2.reasoning_tokens || u2.total_reasoning_tokens,
      input_cached: u2.prompt_tokens_details && u2.prompt_tokens_details.cached_tokens
    };
  }
  return null;
}

export function setUsageHeaders(reply, usage) {
  if (!reply || !usage) return;
  if (usage.total !== undefined) reply.header('X-Token-Usage-Total', String(usage.total));
  if (usage.input !== undefined) reply.header('X-Token-Usage-Input', String(usage.input));
  if (usage.input_cached !== undefined) reply.header('X-Token-Usage-Input-Cached', String(usage.input_cached));
  if (usage.output !== undefined) reply.header('X-Token-Usage-Output', String(usage.output));
  if (usage.reasoning !== undefined) reply.header('X-Token-Usage-Reasoning', String(usage.reasoning));
}
