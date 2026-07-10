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

test('exposed-via-dnat flags only the admin-port forward, not the web redirect', () => {
  const { findings } = FS.lint(FS.parse(sample('iptables-portforward.txt')));
  const dnat = findings.filter((f) => f.id === 'exposed-via-dnat');
  // The 2222→22 ssh publish is flagged; the 8080→8006 redirect (not an admin
  // port) is not — so exactly one finding, about ssh.
  assert.equal(dnat.length, 1);
  assert.match(dnat[0].title, /ssh/);
});

test('shadowed-rule flags a rule whose CIDR is a subset of an earlier same-action rule', () => {
  const rs = [
    '*filter',
    ':INPUT ACCEPT [0:0]',
    '-A INPUT -s 10.0.0.0/8 -j DROP',
    '-A INPUT -s 10.0.0.5/32 -j DROP',
    'COMMIT',
  ].join('\n');
  const { findings } = FS.lint(FS.parse(rs));
  assert.ok(findings.some((f) => f.id === 'shadowed-rule'));
});

test('exposed-admin-port covers data/admin services beyond ssh', () => {
  const { findings } = FS.lint(FS.parse(sample('iptables-exposed-services.txt')));
  const exposed = findings.filter((f) => f.id === 'exposed-admin-port');
  const services = exposed.map((f) => f.title);
  // Each authless / high-value service accepted from 0.0.0.0/0 is flagged.
  for (const svc of ['docker-api', 'elasticsearch', 'memcached', 'smb', 'mssql']) {
    assert.ok(services.some((t) => t.includes(svc)), `expected ${svc} flagged`);
  }
  // VNC is only allowed from 10.0.0.0/8, so it must NOT be flagged as exposed.
  assert.ok(!services.some((t) => t.includes('vnc')), 'vnc is source-restricted, not exposed');
});

test('the sample set exercises all eight smells', () => {
  const seen = new Set();
  for (const name of Object.keys(EXPECTED)) {
    for (const id of lintIds(name)) seen.add(id);
  }
  for (const id of ALL_SMELLS) {
    assert.ok(seen.has(id), `no sample triggers '${id}'`);
  }
});
