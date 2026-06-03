'use strict';

// The packet trace's full NAT model is FirewallScope's distinctive feature:
// nat/PREROUTING DNAT/REDIRECT rewrites the packet before filter, and
// nat/POSTROUTING SNAT/MASQUERADE rewrites it after filter accepts. These
// exercise both walks against the port-forward sample (a realistic edge router).

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { loadFirewallScope, sample } = require('./helper');

const FS = loadFirewallScope();
const portforward = () => FS.parse(sample('iptables-portforward.txt'));

test('trace applies a nat/PREROUTING DNAT before the filter chain (web publish)', () => {
  const r = FS.trace(portforward(), {
    direction: 'forward',
    protocol: 'tcp',
    dport: 80,
    source: '203.0.113.9',
    iif: 'eth0',
  });
  assert.equal(r.error, null);
  assert.equal(r.verdict, 'ACCEPT');

  const dnat = r.steps.find((s) => s.type === 'dnat');
  assert.ok(dnat, 'a DNAT rewrite step is recorded');
  assert.equal(dnat.after.destination, '10.0.0.10');
  assert.equal(dnat.after.dport, 80);
});

test('DNAT rewrites the port for the ssh jumpbox publish (2222 → 22)', () => {
  const r = FS.trace(portforward(), {
    direction: 'forward',
    protocol: 'tcp',
    dport: 2222,
    source: '203.0.113.9',
    iif: 'eth0',
  });
  assert.equal(r.verdict, 'ACCEPT');

  const dnat = r.steps.find((s) => s.type === 'dnat');
  assert.ok(dnat);
  assert.equal(dnat.before.dport, 2222);
  assert.equal(dnat.after.destination, '10.0.0.20');
  assert.equal(dnat.after.dport, 22);
});

test('trace applies nat/POSTROUTING MASQUERADE after filter on the way out', () => {
  const r = FS.trace(portforward(), {
    direction: 'output',
    protocol: 'tcp',
    dport: 443,
    source: '10.0.0.10',
    destination: '8.8.8.8',
    oif: 'eth0',
  });
  assert.equal(r.verdict, 'ACCEPT');

  const snat = r.steps.find((s) => s.type === 'snat');
  assert.ok(snat, 'a SNAT / MASQUERADE step is recorded');
  assert.equal(snat.before.source, '10.0.0.10');
  // MASQUERADE resolves to the outgoing-interface IP at runtime; the model
  // surfaces it as the interface placeholder rather than guessing an address.
  assert.equal(snat.after.source, '<eth0>');
});

test('a source outside the MASQUERADE range is left unrewritten', () => {
  const r = FS.trace(portforward(), {
    direction: 'output',
    protocol: 'tcp',
    dport: 443,
    source: '192.168.1.50',
    destination: '8.8.8.8',
    oif: 'eth0',
  });
  assert.ok(!r.steps.some((s) => s.type === 'snat'), 'no SNAT step for an out-of-range source');
});
