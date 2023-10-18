export function removeEdgeQuotes(input: string): string {
  return input.replace(/^["']|["']$/g, "");
}
