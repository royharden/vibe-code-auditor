import type { FetchedFile } from "../fetch-target.ts";
import { auditSecrets } from "./secrets.ts";
import { auditHeaders } from "./headers.ts";
import { auditAuth } from "./auth.ts";
import { auditA11y } from "./a11y.ts";
import { auditSeo } from "./seo.ts";
import { auditPerformance } from "./performance.ts";

import type { Finding } from "./secrets.ts";

export type { Finding };

export function runAuditors(files: FetchedFile[], mode: string): Finding[] {
  const findings: Finding[] = [];
  findings.push(...auditSecrets(files, mode));
  findings.push(...auditHeaders(files, mode));
  findings.push(...auditAuth(files, mode));
  findings.push(...auditA11y(files, mode));
  findings.push(...auditSeo(files, mode));
  findings.push(...auditPerformance(files, mode));
  return findings;
}
