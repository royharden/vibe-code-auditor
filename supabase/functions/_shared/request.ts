import { json } from "./usage.ts";

export type BodyResult = { ok: true; data: Record<string, unknown> } | { ok: false; response: Response };

// Reads a JSON object body, streaming with a hard byte cap (413 above it) so an oversized
// request is never fully buffered or parsed.
export async function readJsonBody(req: Request, maxBytes: number): Promise<BodyResult> {
  const tooLarge = () => ({ ok: false as const, response: json({ error: "Request body too large" }, 413) });
  const invalid = () => ({ ok: false as const, response: json({ error: "Invalid JSON body" }, 400) });

  const declared = Number(req.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > maxBytes) return tooLarge();

  const reader = req.body?.getReader();
  if (!reader) return invalid();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      total += value.byteLength;
      if (total > maxBytes) {
        reader.cancel().catch(() => {});
        return tooLarge();
      }
      chunks.push(value);
    }
  } catch {
    return invalid();
  }

  const buf = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    buf.set(c, off);
    off += c.byteLength;
  }
  let data: unknown;
  try {
    data = JSON.parse(new TextDecoder().decode(buf));
  } catch {
    return invalid();
  }
  if (!isRecord(data)) return invalid();
  return { ok: true, data };
}

export function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

// Strings are truncated to `max` chars; anything else becomes undefined (dropped by JSON.stringify).
export function clip(v: unknown, max: number): string | undefined {
  return typeof v === "string" ? v.slice(0, max) : undefined;
}
