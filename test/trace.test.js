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

test('trace records a skip (not a guess) for matches it does not model', () => {
  const rs = [
    '*filter',
    ':INPUT DROP [0:0]',
    '-A INPUT -p tcp --dport 22 -m limit --limit 3/min -j ACCEPT',
    '-A INPUT -p tcp --dport 80 -j ACCEPT',
    'COMMIT',
  ].join('\n');
  const r = FS.trace(FS.parse(rs), { direction: 'input', protocol: 'tcp', dport: 22, source: '1.2.3.4' });

  const skip = r.steps.find((s) => s.type === 'skip');
  assert.ok(skip, 'the -m limit rule is skipped rather than guessed at');
  assert.match(skip.reason, /does not model/i);
  // The skipped ACCEPT no longer fires, so the packet falls through to DROP.
  assert.equal(r.verdict, 'DROP');
});
