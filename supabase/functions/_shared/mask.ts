const SENSITIVE_TOKEN = /(sk-|sk-ant-|AKIA|ghp_|github_pat_|xox[bp]-|AIza|sk_live_|rk_live_|BEGIN .*PRIVATE KEY|eyJ[A-Za-z0-9_-]{10,}\.)/;

function maskKey(value: string): string {
  if (value.length <= 8) return value.slice(0, 1) + "…" + value.slice(-1);
  return value.slice(0, 4) + "…" + value.slice(-4);
}

function hashText(text: string): string {
  const FNV = 0x811c9dc5;
  let h = FNV >>> 0;
  for (let i = 0; i < text.length; i++) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return ("00000000" + h.toString(16)).slice(-8);
}

export function makeMasker() {
  return {
    mask(value: string): string {
      return maskKey(value);
    },
    hash(value: string): string {
      return hashText(value);
    },
    containsSensitive(text: string): boolean {
      return SENSITIVE_TOKEN.test(text);
    },
  };
}

export function maskEvidence(value: string): string {
  return maskKey(value);
}

export function hashSecret(value: string): string {
  return hashText(value);
}

export function isSensitiveText(text: string): boolean {
  return SENSITIVE_TOKEN.test(text);
}
