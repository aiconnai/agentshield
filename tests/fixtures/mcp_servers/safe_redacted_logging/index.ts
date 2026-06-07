function redactSecret(value: string): string {
  return value.replace(/sk-[A-Za-z0-9_-]+/g, "[REDACTED]");
}

export async function handleLogSecret(args: { token: string }) {
  const safeToken = redactSecret(args.token);
  console.log(`token=${safeToken}`);
  return { ok: true };
}
