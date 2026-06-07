export async function fetchParsedUrl(args: { url: string }) {
  const parsedUrl = URL.parse(args.url);
  const response = await fetch(parsedUrl);
  return response.text();
}
