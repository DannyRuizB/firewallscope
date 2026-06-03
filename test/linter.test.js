'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { loadFirewallScope, sample } = require('./helper');

const FS = loadFirewallScope();

function lintIds(name) {
  const { findings } = FS.lint(FS.parse(sample(name)));
  return new Set(findings.map((f) => f.id));
}

// Each known-bad sample must raise (at least) these smells. Asserting a subset
// keeps the test stable if new smells are added later.
const EXPECTED = {
  'iptables-leaky.txt': ['missing-input-drop', 'exposed-admin-port', 'permissive-accept', 'fallthrough-accept'],
  'iptables-shadowed.txt': ['shadowed-rule', 'rule-after-policy-drop'],
  'iptables-portforward.txt': ['exposed-via-dnat'],
  'ufw-status.txt': ['loopback-not-allowed'],
};

for (const [name, ids] of Object.entries(EXPECTED)) {
  test(`lint flags [${ids.join(', ')}] in ${name}`, () => {
    const found = lintIds(name);
    for (const id of ids) assert.ok(found.has(id), `expected smell '${id}' in ${name}`);
  });
}

test('lint result carries a numeric counts summary', () => {
  const { counts } = FS.lint(FS.parse(sample('iptables-leaky.txt')));
  for (const k of ['error', 'warning', 'info', 'total']) {
    assert.equal(typeof counts[k], 'number', `counts.${k}`);
  }
  assert.equal(counts.total, counts.error + counts.warning + counts.info);
});

const ALL_SMELLS = [
  'exposed-admin-port',
  'exposed-via-dnat',
  'fallthrough-accept',
  'loopback-not-allowed',
  'missing-input-drop',
  'permissive-accept',
  'rule-after-policy-drop',
  'shadowed-rule',
];

test('the sample set exercises all eight smells', () => {
  const seen = new Set();
  for (const name of Object.keys(EXPECTED)) {
    for (const id of lintIds(name)) seen.add(id);
  }
  for (const id of ALL_SMELLS) {
    assert.ok(seen.has(id), `no sample triggers '${id}'`);
  }
});
