import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Module from 'node:module';
import ts from 'typescript';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
const filename = fileURLToPath(new URL('../src/components/OriginAssessment.tsx', import.meta.url));
const component = new Module(filename);
component.filename = filename;
component.paths = Module._nodeModulePaths(path.dirname(filename));
component._compile(ts.transpileModule(fs.readFileSync(filename, 'utf8'), {
  compilerOptions: { jsx: ts.JsxEmit.ReactJSX, module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 },
}).outputText, filename);
const render = props => renderToStaticMarkup(React.createElement(component.exports.default, props));

test('old analyses show missing origin evidence without inventing a score', () => {
  const html = render({});
  assert.match(html, /Not Available/);
  assert.match(html, /Candidate relay: Not established/);
  assert.match(html, /Re-analyze this email/);
  assert.match(html, /does not identify a person/);
});

test('infrastructure interpretation preserves source and uncertainty and escapes hostile content', () => {
  const html = render({ origin: { score: 59, level: 'LIMITED', candidate_ip: '8.8.8.8',
    limitations: ['Untrusted header provenance'],
    infrastructure_indicators: [{ kind: 'HOSTING', basis: 'INFERRED', source: 'geoip', field: 'organization', value: '<script>alert(1)</script>' }] },
    attribution: { findings: [{ kind: 'Human actor identity', status: 'INSUFFICIENT EVIDENCE', reason: 'No identity established.' }] },
  });
  assert.match(html, /59\/100 · LIMITED/);
  assert.match(html, /INFERRED/);
  assert.match(html, /geoip/);
  assert.match(html, /INSUFFICIENT EVIDENCE/);
  assert.match(html, /&lt;script&gt;/);
  assert.doesNotMatch(html, /<script>/);
});

test('network origin shows unknown privacy separately from a reported negative and preserves provenance', () => {
  const html = render({origin:{score:34,level:'MEDIUM',candidate_ip:'8.8.8.8',probable_origin:{ip:'8.8.8.8',is_proxy:false,is_vpn:true,is_tor:null,data_source:'IPinfo / MaxMind',field_sources:{latitude:'MaxMind',asn:'IPinfo'},mail_cloud_provider:'Google / Gmail'}}});
  assert.match(html,/Probable Network Origin/);
  assert.match(html,/Yes \(reported\)/);
  assert.match(html,/No \(reported\)/);
  assert.match(html,/Unknown \/ not supplied by provider/);
  assert.match(html,/latitude: MaxMind/);
  assert.match(html,/approximate network origin/);
  assert.match(html,/Origin confidence: 34\/100 · MEDIUM/);
});
