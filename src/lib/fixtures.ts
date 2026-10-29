export interface FixtureFile {
  path: string;
  kind: string;
  status: number;
  size: number;
  gzipSize?: number | null;
  headers: Record<string, string>;
  text: string;
}

export interface Fixture {
  id: string;
  name: string;
  description: string;
  mode: "url" | "repo";
  target: string;
  files: FixtureFile[];
}

// Deliberately invalid, wholly synthetic scanner probes. Never use for auth.
// Assemble the recognisable prefix so no complete key-shaped literal is stored.
const syntheticOpenAiProbe = ["sk", "proj", "SYNTHETIC", "NOT", "A", "CREDENTIAL", "0".repeat(24)].join("-");
const encodeProbePart = (value: object) => btoa(JSON.stringify(value))
  .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const syntheticServiceJwt = [
  encodeProbePart({ alg: "none", typ: "JWT", synthetic: true }),
  encodeProbePart({ role: "service_role", iss: "https://demo.invalid", synthetic: true }),
  "INVALID_SYNTHETIC_SIGNATURE",
].join(".");

const leakyTodoHtml = `<!DOCTYPE html>
<html>
<head>
  <title>Leaky Todo</title>
  <script src="/assets/index-9f8a2b.js"></script>
  <link rel="stylesheet" href="/assets/index-3c4d5e.css">
</head>
<body>
  <div id="root"></div>
  <img src="/hero.png">
  <input type="text" name="todo">
</body>
</html>`;

const leakyTodoJs = `// Leaky Todo bundle (fixture)
const OPENAI_KEY = "${syntheticOpenAiProbe}";
const serviceKey = "${syntheticServiceJwt}";
fetch("https://api.openai.com/v1/models", { headers: { Authorization: "Bearer " + OPENAI_KEY } });
//# sourceMappingURL=index-9f8a2b.js.map`;

const supabaseStarterMigration = `-- Supabase Starter fixture migration
create table if not exists posts (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  body text,
  user_id uuid
);

create policy "anyone can update posts" on posts for update
  using (true);

create policy "anyone can delete posts" on posts for delete
  using (true);
`;

const supabaseStarterEnv = `SUPABASE_URL=https://demo.supabase.co
OPENAI_API_KEY=${syntheticOpenAiProbe}
STRIPE_WEBHOOK_SECRET=SYNTHETIC_NOT_A_CREDENTIAL
`;

const wellConfiguredHtml = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Well-configured site — a solid production example</title>
  <meta name="description" content="This fixture shows a well-configured site with proper headers, accessibility, SEO and performance hygiene.">
  <link rel="canonical" href="https://well-configured.example.com/">
  <meta property="og:title" content="Well-configured site">
  <meta property="og:description" content="A well-configured example site.">
  <meta property="og:image" content="https://well-configured.example.com/og.png">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <script defer src="/assets/app-1a2b3c4d.js"></script>
  <link rel="stylesheet" href="/assets/app-1a2b3c4d.css">
</head>
<body>
  <h1>Welcome</h1>
  <h2>Features</h2>
  <img src="/hero.png" alt="Product hero" width="1200" height="600">
  <form><label for="email">Email</label><input id="email" type="email"></form>
  <p>This page has enough visible content to avoid the empty SPA shell finding, because it renders meaningful static text server-side for crawlers and readers alike.</p>
</body>
</html>`;

export const FIXTURES: Fixture[] = [
  {
    id: "leaky-todo",
    name: "Leaky Todo",
    description: "A deployed app with an invalid synthetic OpenAI probe in the bundle, an unsigned synthetic service_role JWT, no CSP, and exposed source maps.",
    mode: "url",
    target: "https://leaky-todo.demo.invalid/",
    files: [
      {
        path: "https://leaky-todo.demo.invalid/",
        kind: "page",
        status: 200,
        size: 420,
        gzipSize: 260,
        headers: {
          "content-type": "text/html",
          "x-powered-by": "Express",
        },
        text: leakyTodoHtml,
      },
      {
        path: "https://leaky-todo.demo.invalid/assets/index-9f8a2b.js",
        kind: "asset",
        status: 200,
        size: 312_000,
        gzipSize: 98_000,
        headers: { "content-type": "application/javascript" },
        text: leakyTodoJs,
      },
      {
        path: "https://leaky-todo.demo.invalid/assets/index-3c4d5e.css",
        kind: "asset",
        status: 200,
        size: 8_400,
        gzipSize: 2_800,
        headers: { "content-type": "text/css" },
        text: "body{margin:0}",
      },
      {
        path: "https://leaky-todo.demo.invalid/assets/index-9f8a2b.js.map",
        kind: "sourcemap",
        status: 200,
        size: 512_000,
        gzipSize: 120_000,
        headers: { "content-type": "application/json" },
        text: '{"version":3,"sources":["src/index.tsx"]}',
      },
      {
        path: "https://leaky-todo.demo.invalid/robots.txt",
        kind: "wellknown",
        status: 404,
        size: 0,
        gzipSize: null,
        headers: {},
        text: "",
      },
    ],
  },
  {
    id: "supabase-starter",
    name: "Supabase Starter repo",
    description: "A repo whose migrations are missing RLS, with a committed .env file.",
    mode: "repo",
    target: "github.com/demo/supabase-starter",
    files: [
      {
        path: "package.json",
        kind: "package",
        status: 200,
        size: 640,
        headers: {},
        text: '{"dependencies":{"react":"^18.2.0","@supabase/supabase-js":"^2.0.0","vite":"^5.0.0"}}',
      },
      {
        path: "supabase/migrations/0001_init.sql",
        kind: "migration",
        status: 200,
        size: 820,
        headers: {},
        text: supabaseStarterMigration,
      },
      {
        path: ".env",
        kind: "env",
        status: 200,
        size: 210,
        headers: {},
        text: supabaseStarterEnv,
      },
      {
        path: "src/supabase.ts",
        kind: "source",
        status: 200,
        size: 300,
        headers: {},
        text: 'import { createClient } from "@supabase/supabase-js";\nexport const db = createClient(URL, ANON_KEY);',
      },
    ],
  },
  {
    id: "well-configured",
    name: "Well-configured site",
    description: "A hardened deployment: strict headers, clean accessibility and SEO, grade A.",
    mode: "url",
    target: "https://well-configured.demo.invalid/",
    files: [
      {
        path: "https://well-configured.demo.invalid/",
        kind: "page",
        status: 200,
        size: 1_480,
        gzipSize: 720,
        headers: {
          "content-type": "text/html",
          "content-security-policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'",
          "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
          "x-content-type-options": "nosniff",
          "referrer-policy": "strict-origin-when-cross-origin",
          "permissions-policy": "camera=(), microphone=(), geolocation=()",
          "cache-control": "max-age=3600",
        },
        text: wellConfiguredHtml,
      },
      {
        path: "https://well-configured.demo.invalid/assets/app-1a2b3c4d.js",
        kind: "asset",
        status: 200,
        size: 84_000,
        gzipSize: 28_000,
        headers: {
          "content-type": "application/javascript",
          "content-encoding": "br",
          "cache-control": "public, max-age=31536000, immutable",
        },
        text: "console.log('app');",
      },
      {
        path: "https://well-configured.demo.invalid/assets/app-1a2b3c4d.css",
        kind: "asset",
        status: 200,
        size: 9_200,
        gzipSize: 2_400,
        headers: {
          "content-type": "text/css",
          "content-encoding": "br",
          "cache-control": "public, max-age=31536000, immutable",
        },
        text: "body{font-family:sans-serif}",
      },
      {
        path: "https://well-configured.demo.invalid/robots.txt",
        kind: "wellknown",
        status: 200,
        size: 68,
        gzipSize: null,
        headers: {},
        text: "User-agent: *\nAllow: /\nSitemap: https://well-configured.demo.invalid/sitemap.xml",
      },
      {
        path: "https://well-configured.demo.invalid/sitemap.xml",
        kind: "wellknown",
        status: 200,
        size: 320,
        gzipSize: null,
        headers: {},
        text: '<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://well-configured.demo.invalid/</loc></url></urlset>',
      },
    ],
  },
];
