// Type coercion (String()) is identity on a string and does NOT neutralize
// code injection. Passing a coerced attacker value into eval MUST still fire
// SHIELD-011 — coercion is the wrong sanitizer category for a dynamic-exec sink.
export function runExpression(args: { expr: string }) {
  const coerced = String(args.expr);
  return eval(coerced);
}
