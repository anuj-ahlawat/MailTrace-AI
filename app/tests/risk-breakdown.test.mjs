// Render the real TSX component without adding a test framework dependency.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Module from 'node:module';
import ts from 'typescript';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
const filename = fileURLToPath(new URL('../components/RiskBreakdown.tsx', import.meta.url));
const component = new Module(filename);
component.filename = filename;
component.paths = Module._nodeModulePaths(path.dirname(filename));
component._compile(ts.transpileModule(fs.readFileSync(filename, 'utf8'), {
  compilerOptions: { jsx: ts.JsxEmit.ReactJSX, module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 },
}).outputText, filename);
const render = analysis => renderToStaticMarkup(React.createElement(component.exports.default, { analysis }));
const row = (category, points = 0, maximum_points = 15) => ({ category, points, maximum_points });

test('screenshot regression: 5.62 AI points fill 5.62/15, and 6.37 rounds to 6', () => {
  const html = render({
    contributions: [row('url', .75), row('ai', 5.62)], weighted_score: 6.37, risk_score: 6, risk_version: '2.0',
    ml: { status: 'Available', label: 'SPAM', confidence: .81342248, probabilities: { PHISHING: .04637663, BEC: .00301337, SPAM: .81342248 } },
  });
  assert.match(html, /max="15" value="5.62" aria-label="AI model risk contribution"/);
  assert.match(html, /max="15" value="0.75"/);
  assert.match(html, /weighted evidence 6.37\/100 · final risk 6\/100 \(rounded\)/);
  assert.match(html, /81.34% class probability/);
  assert.match(html, /0.4 × P\(spam\)/);
});

test('zero weights and custom weights use valid category ranges', () => {
  const html = render({ contributions: [row('ai', 0, 0), row('url', 10, 40)] });
  assert.doesNotMatch(html, /max="0"/);
  assert.match(html, /Disabled by scoring settings/);
  assert.match(html, /max="40" value="10"/);
});

test('unverified authentication and failed providers are not shown as passed checks', () => {
  const html = render({ contributions: [row('authentication'), row('intelligence'), row('ai')],
    forensics: { authentication: { spf: { reported_result: 'PASS' }, dkim: { local_verification: { status: 'Not Configured' } } } },
    intelligence: [{ providers: [{ provider: 'geoip', status: 'Available' }, { provider: 'virustotal', status: 'Rate Limited' }] }],
  });
  assert.match(html, /Header-reported results only; not independently verified/);
  assert.match(html, /No reputation results \(Rate Limited\)/);
  assert.match(html, /Model unavailable/);
});

test('not applicable differs from missing evidence and partial reputation remains visible', () => {
  const contributions = [row('attachment'), row('url'), row('headers'), row('intelligence')];
  const html = render({ contributions, forensics: { attachments: [], urls: [], received_chain: [] },
    omitted_enrichment_indicators: 8,
    intelligence: [{ providers: [{ provider: 'virustotal', status: 'Available' }, { provider: 'abuseipdb', status: 'Unavailable' }] }],
  });
  assert.match(html, /Not applicable: no attachments/);
  assert.match(html, /Not applicable: no URLs/);
  assert.match(html, /No relay headers to check/);
  assert.match(html, /1 reputation reports available; other lookups: Unavailable; 8 indicators not checked/);
  assert.match(render({ contributions }), /Attachment evidence unavailable/);
});

test('rule adjustment is distinguished from weighted evidence in the final total', () => {
  const html = render({ contributions: [row('correlated_evidence', 60, 85)], weighted_score: 15, risk_score: 75 });
  assert.match(html, /final risk 75\/100 \(rounded after adding 60 correlation points\)/);
  assert.match(html, /Correlation adjustment/);
});

test('phishing model review floor explains the reported 12-to-60 correction', () => {
  const html = render({ contributions: [row('ai', 12.11), row('model_review', 47.89, 87.89)], weighted_score: 12.11, risk_score: 60,
    model_review: { reason: 'Model predicts PHISHING: HIGH review priority required', minimum_score: 60, limitation: 'Policy review minimum, not additional forensic evidence' } });
  assert.match(html, /final risk 60\/100 \(rounded after adding 47.89 model review points\)/);
  assert.match(html, /Model review adjustment/);
  assert.match(html, /Minimum review score: 60\/100/);
});
