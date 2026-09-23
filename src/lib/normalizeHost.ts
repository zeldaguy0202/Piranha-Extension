// Accepts a bare domain or full URL and returns a normalized hostname for storage/matching.
export function normalizeHost(input: string): string {
  const trimmed = input.trim();
  if (!trimmed) return "";
  try {
    const url = new URL(trimmed.includes("://") ? trimmed : `https://${trimmed}`);
    return url.hostname.replace(/^www\./, "");
  } catch {
    return trimmed.toLowerCase().replace(/^www\./, "");
  }
}
