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
