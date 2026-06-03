'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { loadFirewallScope, sample } = require('./helper');

const FS = loadFirewallScope();
const leaky = () => FS.parse(sample('iptables-leaky.txt'));

test('trace accepts SSH when an explicit ssh ACCEPT rule matches', () => {
  const r = FS.trace(leaky(), { direction: 'input', protocol: 'tcp', dport: 22, source: '203.0.113.5' });
  assert.equal(r.error, null);
  assert.equal(r.verdict, 'ACCEPT');
  assert.ok(r.finalRule, 'a concrete matching rule should be reported');
});

test('an ACCEPT-policy INPUT chain accepts even an unmatched port (the leak)', () => {
  const r = FS.trace(leaky(), { direction: 'input', protocol: 'tcp', dport: 9999, source: '203.0.113.5' });
  assert.equal(r.verdict, 'ACCEPT');
});

test('trace reports an error for an invalid direction', () => {
  const r = FS.trace(leaky(), { direction: 'sideways' });
  assert.ok(r.error);
  assert.match(r.error, /direction/i);
});

test('trace reports an error against an unparsed ruleset', () => {
  const r = FS.trace(FS.parse('garbage'), { direction: 'input' });
  assert.ok(r.error);
});
