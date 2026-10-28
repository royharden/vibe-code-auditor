import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { FIXTURES } from '../src/lib/fixtures.ts';
import { auditSecrets } from '../supabase/functions/_shared/auditors/secrets.ts';

// what_bug_this_catches: sanitizing demo credentials must preserve real scanner
// coverage; the previous two-part synthetic JWT never reached the role detector.
test('offline probes are explicitly synthetic and reach the secret detectors', () => {
  const fixture = FIXTURES.find((item) => item.id === 'leaky-todo');
  const bundle = fixture.files.find((file) => file.kind === 'asset').text;
  const jwt = bundle.match(/const serviceKey = "([^"]+)"/)[1];
  const [header, payload, signature] = jwt.split('.');
  assert.equal(JSON.parse(Buffer.from(header, 'base64url')).alg, 'none');
  assert.equal(JSON.parse(Buffer.from(payload, 'base64url')).iss, 'https://demo.invalid');
  assert.equal(JSON.parse(Buffer.from(payload, 'base64url')).synthetic, true);
  assert.equal(signature, 'INVALID_SYNTHETIC_SIGNATURE');
  assert.ok(bundle.includes('SYNTHETIC-NOT-A-CREDENTIAL'));
  const findings = auditSecrets(fixture.files, fixture.mode);
  assert.ok(findings.some((item) => item.rule_id === 'openai_key'));
  assert.ok(findings.some((item) => item.rule_id === 'service_role_jwt'));
  assert.ok(findings.every((item) => !item.evidence.includes(jwt)));
});

test('tracked fixture source stores no complete credential-shaped literals', () => {
  const source = readFileSync(new URL('../src/lib/fixtures.ts', import.meta.url), 'utf8');
  assert.equal(/sk-(?:proj-)?[A-Za-z0-9_-]{20,}/.test(source), false);
  assert.equal(/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}/.test(source), false);
});
