'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { loadFirewallScope, sample } = require('./helper');

const FS = loadFirewallScope();

test('mergeForDiff summarises rule changes between two revisions', () => {
  const before = FS.parse(sample('iptables-save.txt'));
  const after = FS.parse(sample('iptables-save-after.txt'));
  const d = FS.mergeForDiff(before, after);

  assert.ok(!d.error);
  assert.equal(d.isDiff, true);
  assert.equal(d.format, 'iptables');
  assert.ok(
    d.diff.addedRules > 0 || d.diff.removedRules > 0,
    'two different revisions should show added or removed rules',
  );
});

test('mergeForDiff flags rules moved within a chain', () => {
  const before = FS.parse(sample('iptables-save.txt'));
  const after = FS.parse(sample('iptables-save-after.txt'));
  const d = FS.mergeForDiff(before, after);
  assert.ok(d.diff.movedRules >= 1, 'expected at least one moved rule');
});

test('mergeForDiff refuses to diff across firewall formats', () => {
  const ipt = FS.parse(sample('iptables-save.txt'));
  const nft = FS.parse(sample('nft-ruleset.txt'));
  const d = FS.mergeForDiff(ipt, nft);

  assert.ok(d.error);
  assert.match(d.error, /format/i);
});
