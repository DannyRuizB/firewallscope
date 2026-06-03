'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { loadFirewallScope, sample } = require('./helper');

const FS = loadFirewallScope();

const FORMAT_BY_SAMPLE = {
  'iptables-save.txt': 'iptables',
  'iptables-leaky.txt': 'iptables',
  'iptables-shadowed.txt': 'iptables',
  'iptables-portforward.txt': 'iptables',
  'ip6tables-save.txt': 'ip6tables',
  'nft-ruleset.txt': 'nftables',
  'ufw-status.txt': 'ufw',
};

test('detectFormat identifies every sample format', () => {
  for (const [name, expected] of Object.entries(FORMAT_BY_SAMPLE)) {
    assert.equal(FS.detectFormat(sample(name)), expected, name);
  }
});

test('detectFormat returns null for text that is not a ruleset', () => {
  assert.equal(FS.detectFormat('just some prose, definitely not a firewall'), null);
});

test('parse builds a format/tables/chains/rules tree', () => {
  const r = FS.parse(sample('iptables-save.txt'));
  assert.equal(r.format, 'iptables');
  assert.equal(r.error, null);
  assert.ok(Array.isArray(r.tables) && r.tables.length > 0);

  const chain = r.tables[0].chains[0];
  assert.equal(typeof chain.name, 'string');
  assert.ok(Array.isArray(chain.rules));
});

test('parse surfaces an error object (never throws) on undetectable input', () => {
  const r = FS.parse('not a ruleset at all');
  assert.equal(r.format, null);
  assert.ok(r.error);
  // NB: r.tables is created inside the vm sandbox, so it has the sandbox's
  // Array.prototype — deepStrictEqual against a main-realm [] would fail on the
  // prototype check. Array.isArray works across realms; assert on length.
  assert.ok(Array.isArray(r.tables) && r.tables.length === 0);
});

test('every sample format parses cleanly into at least one table', () => {
  for (const name of Object.keys(FORMAT_BY_SAMPLE)) {
    const r = FS.parse(sample(name));
    assert.equal(r.error, null, `${name} should parse without error`);
    assert.ok(r.tables.length > 0, `${name} should yield tables`);
  }
});

test('parse preserves nftables table families', () => {
  const r = FS.parse(sample('nft-ruleset.txt'));
  assert.equal(r.format, 'nftables');
  assert.equal(r.tables.find((t) => t.name === 'filter').family, 'inet');
  assert.equal(r.tables.find((t) => t.name === 'nat').family, 'ip');
});

test('parse reads ufw status rules into the common model', () => {
  const r = FS.parse(sample('ufw-status.txt'));
  assert.equal(r.format, 'ufw');
  const rules = r.tables[0].chains.flatMap((c) => [...c.rules]);
  assert.ok(rules.some((rule) => rule.tokens && rule.tokens.dport === '22'));
});

test('parse detects ip6tables and yields a filter table', () => {
  const r = FS.parse(sample('ip6tables-save.txt'));
  assert.equal(r.format, 'ip6tables');
  assert.ok(r.tables.some((t) => t.name === 'filter'));
});
