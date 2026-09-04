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
  'iptables-portforward.txt': ['exposed-via-dnat', 'unlimited-log', 'unlimited-icmp-echo', 'missing-loopback-spoof-drop', 'log-without-prefix', 'dnat-to-loopback'],
  'ufw-status.txt': ['loopback-not-allowed', 'unrestricted-egress'],
  'iptables-exposed-services.txt': ['exposed-admin-port', 'wide-open-port-range', 'overbroad-source-trust'],
  'iptables-router-sloppy.txt': ['forward-no-default-deny', 'missing-established-accept', 'masquerade-any-source', 'drop-without-log', 'missing-invalid-drop', 'unused-chain', 'duplicate-rule', 'unlimited-icmp-echo', 'unrestricted-egress', 'mac-based-trust', 'admin-port-no-rate-limit', 'bogon-source-accept', 'dnat-unscoped', 'dnat-no-hairpin', 'rate-limit-not-per-source', 'rate-limit-drop-inverted', 'rate-limit-accept-inverted', 'source-port-trust'],
  'ip6tables-no-icmpv6.txt': ['icmpv6-blocked', 'unlimited-log'],
  'iptables-no-pmtud.txt': ['icmp-pmtud-blocked'],
  'nft-v4only.txt': ['ipv6-unfiltered', 'unrestricted-egress'],
  'iptables-dnat-dead.txt': ['dnat-forward-blocked', 'exposed-via-dnat'],
  'ufw-default-allow.txt': ['allow-under-default-allow', 'missing-input-drop'],
  'iptables-reflector.txt': ['udp-amplifier-exposed', 'exposed-admin-port'],
  'ufw-default-deny-noop.txt': ['deny-under-default-deny'],
  'iptables-docker-open.txt': ['docker-user-unfiltered', 'exposed-admin-port', 'missing-invalid-drop', 'unrestricted-egress'],
  'iptables-notrack-dns.txt': ['notrack-defeats-state-match'],
  'iptables-ftp-helper.txt': ['conntrack-helper-enabled'],
  'iptables-notrack-oneway.txt': ['notrack-one-way'],
  'iptables-accept-all-dead.txt': ['unreachable-after-accept-all', 'permissive-accept'],
  'iptables-recent-oneway.txt': ['recent-one-way'],
  'iptables-dport-no-proto.txt': ['port-match-without-protocol'],
  'iptables-reject-mismatch.txt': ['reject-type-mismatch'],
  'iptables-port-wrong-proto.txt': ['port-match-protocol-mismatch'],
  'iptables-nat-state-dead.txt': ['nat-state-match-dead'],
  'iptables-tcp-flags-dead.txt': ['tcp-flags-never-match'],
  'iptables-syn-on-udp.txt': ['tcp-option-without-tcp'],
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
  'wide-open-port-range',
  'overbroad-source-trust',
  'forward-no-default-deny',
  'missing-established-accept',
  'masquerade-any-source',
  'drop-without-log',
  'missing-invalid-drop',
  'icmpv6-blocked',
  'unused-chain',
  'unlimited-log',
  'duplicate-rule',
  'unlimited-icmp-echo',
  'unrestricted-egress',
  'mac-based-trust',
  'admin-port-no-rate-limit',
  'log-tcp-sequence',
  'missing-loopback-spoof-drop',
  'ipv6-unfiltered',
  'dnat-forward-blocked',
  'bogon-source-accept',
  'log-without-prefix',
  'dnat-unscoped',
  'dnat-no-hairpin',
  'rate-limit-not-per-source',
  'rate-limit-drop-inverted',
  'rate-limit-accept-inverted',
  'icmp-pmtud-blocked',
  'allow-under-default-allow',
  'source-port-trust',
  'udp-amplifier-exposed',
  'deny-under-default-deny',
  'dnat-to-loopback',
  'docker-user-unfiltered',
  'notrack-defeats-state-match',
  'notrack-one-way',
  'conntrack-helper-enabled',
  'unreachable-after-accept-all',
  'recent-one-way',
  'port-match-without-protocol',
  'reject-type-mismatch',
  'port-match-protocol-mismatch',
  'nat-state-match-dead',
  'tcp-flags-never-match',
  'tcp-option-without-tcp',
];

// --- allow-under-default-allow -------------------------------------------

const UFW_HEADER = [
  'Status: active',
  'Logging: on (low)',
];
const UFW_TABLE = [
  '',
  'To                         Action      From',
  '--                         ------      ----',
];

function ufwLint(defaults, rows) {
  const text = [...UFW_HEADER, `Default: ${defaults}`, 'New profiles: skip', ...UFW_TABLE, ...rows].join('\n');
  return FS.lint(FS.parse(text)).findings;
}

test('allow-under-default-allow counts the no-op allows and composes with missing-input-drop', () => {
  const findings = ufwLint('allow (incoming), allow (outgoing), disabled (routed)', [
    '22/tcp                     ALLOW IN    Anywhere',
    '443/tcp                    ALLOW IN    Anywhere',
  ]);
  const hits = findings.filter((f) => f.id === 'allow-under-default-allow');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].chain, 'INPUT');
  assert.equal(hits[0].ruleIdx, 0);
  assert.ok(hits[0].title.startsWith('2 allow'));
  // Two axes, two findings: the open policy (error) AND the decorative list.
  assert.ok(findings.some((f) => f.id === 'missing-input-drop' && f.chain === 'INPUT'));
});

test('allow-under-default-allow never fires under a default-deny policy', () => {
  const findings = ufwLint('deny (incoming), allow (outgoing), disabled (routed)', [
    '22/tcp                     ALLOW IN    Anywhere',
  ]);
  assert.ok(!findings.some((f) => f.id === 'allow-under-default-allow'));
});

test('an allow above a deny still does real work and is spared; allows below it are not', () => {
  const findings = ufwLint('allow (incoming), allow (outgoing), disabled (routed)', [
    '22/tcp                     ALLOW IN    10.0.0.0/8',
    'Anywhere                   DENY IN     10.0.0.0/8',
    '80/tcp                     ALLOW IN    Anywhere',
    '443/tcp                    ALLOW IN    Anywhere',
  ]);
  const hits = findings.filter((f) => f.id === 'allow-under-default-allow');
  assert.equal(hits.length, 1);
  // Only the two allows BELOW the deny are no-ops; the finding anchors there.
  assert.ok(hits[0].title.startsWith('2 allow'));
  assert.equal(hits[0].ruleIdx, 2);
});

test('LIMIT rules keep their throttle and never count as no-op allows', () => {
  const findings = ufwLint('allow (incoming), allow (outgoing), disabled (routed)', [
    '8080/tcp                   LIMIT IN    Anywhere',
  ]);
  assert.ok(!findings.some((f) => f.id === 'allow-under-default-allow'));
});

test('the decorative-ufw sample trips the smell exactly once with three no-ops', () => {
  const { findings } = FS.lint(FS.parse(sample('ufw-default-allow.txt')));
  const hits = findings.filter((f) => f.id === 'allow-under-default-allow');
  assert.equal(hits.length, 1);
  assert.ok(hits[0].title.startsWith('3 allow'));
  // The LIMIT row and the working DENY are not part of the count, and the
  // finding anchors on the first allow after the deny.
  assert.equal(hits[0].ruleIdx, 1);
});

test('a v6 deny below the list cannot save a v4 no-op allow (families judged apart)', () => {
  // ufw prints the whole v6 block after the v4 rules: with the flat-list
  // logic the trailing v6 deny made every v4 allow look functional.
  const findings = ufwLint('allow (incoming), allow (outgoing), disabled (routed)', [
    '80/tcp                     ALLOW IN    Anywhere',
    '23/tcp (v6)                DENY IN     Anywhere (v6)',
  ]);
  const hits = findings.filter((f) => f.id === 'allow-under-default-allow');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].ruleIdx, 0);
});

// --- deny-under-default-deny ----------------------------------------------

test('deny-under-default-deny counts the dead denies and anchors on the first', () => {
  const findings = ufwLint('deny (incoming), allow (outgoing), disabled (routed)', [
    '80/tcp                     ALLOW IN    Anywhere',
    '23/tcp                     DENY IN     Anywhere',
    '445/tcp                    DENY IN     Anywhere',
  ]);
  const hits = findings.filter((f) => f.id === 'deny-under-default-deny');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].chain, 'INPUT');
  assert.equal(hits[0].ruleIdx, 1);
  assert.ok(hits[0].title.startsWith('2 deny'));
});

test('a deny above an allow carves an exception and is spared', () => {
  const findings = ufwLint('deny (incoming), allow (outgoing), disabled (routed)', [
    '80/tcp                     DENY IN     203.0.113.9',
    '80/tcp                     ALLOW IN    Anywhere',
  ]);
  assert.ok(!findings.some((f) => f.id === 'deny-under-default-deny'));
});

test('a deny above a LIMIT is spared too - limit admits traffic a deny can carve', () => {
  const findings = ufwLint('deny (incoming), allow (outgoing), disabled (routed)', [
    '22/tcp                     DENY IN     203.0.113.9',
    '22/tcp                     LIMIT IN    Anywhere',
  ]);
  assert.ok(!findings.some((f) => f.id === 'deny-under-default-deny'));
});

test('REJECT under a deny policy changes the refusal mode and is spared', () => {
  const findings = ufwLint('deny (incoming), allow (outgoing), disabled (routed)', [
    '113/tcp                    REJECT IN   Anywhere',
  ]);
  assert.ok(!findings.some((f) => f.id === 'deny-under-default-deny'));
});

test('under a reject policy the roles swap: reject rules are the no-ops, denies work', () => {
  const findings = ufwLint('reject (incoming), allow (outgoing), disabled (routed)', [
    '113/tcp                    REJECT IN   Anywhere',
    '23/tcp                     DENY IN     Anywhere',
  ]);
  const hits = findings.filter((f) => f.id === 'deny-under-default-deny');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].ruleIdx, 0);
  assert.ok(hits[0].title.startsWith('1 reject'));
});

test('a (log) deny changes what you see and is spared', () => {
  const findings = ufwLint('deny (incoming), allow (outgoing), disabled (routed)', [
    '137/udp                    DENY IN     Anywhere                   (log)',
  ]);
  assert.ok(!findings.some((f) => f.id === 'deny-under-default-deny'));
});

test('never fires under a default-allow policy (that is the other smell)', () => {
  const findings = ufwLint('allow (incoming), allow (outgoing), disabled (routed)', [
    '23/tcp                     DENY IN     Anywhere',
    '80/tcp                     ALLOW IN    Anywhere',
  ]);
  assert.ok(!findings.some((f) => f.id === 'deny-under-default-deny'));
});

test('a v6 allow below the list cannot save a v4 dead deny (families judged apart)', () => {
  // The measured case: a deny added after `allow 80` sits above the v6
  // block, and judging the flat list called it functional when it was dead.
  const findings = ufwLint('deny (incoming), allow (outgoing), disabled (routed)', [
    '80/tcp                     ALLOW IN    Anywhere',
    '80/tcp                     DENY IN     203.0.113.9',
    '80/tcp (v6)                ALLOW IN    Anywhere (v6)',
  ]);
  const hits = findings.filter((f) => f.id === 'deny-under-default-deny');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].ruleIdx, 1);
});

test('the dead-deny sample trips the smell exactly once, on the late v4 deny only', () => {
  const { findings } = FS.lint(FS.parse(sample('ufw-default-deny-noop.txt')));
  const hits = findings.filter((f) => f.id === 'deny-under-default-deny');
  assert.equal(hits.length, 1);
  assert.ok(hits[0].title.startsWith('1 deny'));
  // The denies above the LIMIT are spared, the (log) deny is spared, the
  // REJECT is spared, and the v6 block has nothing after its LIMIT.
  assert.equal(hits[0].ruleIdx, 5);
});

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

test('shadowed-rule detects real IPv6 subsets, not just identical text', () => {
  // 2001:db8:0:1::5/128 lives inside 2001:db8::/32, so the /128 rule is dead.
  const rs = [
    '# Generated by ip6tables-save',
    '*filter',
    ':INPUT ACCEPT [0:0]',
    '-A INPUT -s 2001:db8::/32 -j DROP',
    '-A INPUT -s 2001:db8:0:1::5/128 -j DROP',
    'COMMIT',
  ].join('\n');
  const { findings } = FS.lint(FS.parse(rs));
  assert.ok(
    findings.some((f) => f.id === 'shadowed-rule' && f.ruleIdx === 1),
    'the /128 inside the /32 should be shadowed',
  );
});

test('shadowed-rule does NOT flag an IPv6 address outside the earlier prefix', () => {
  // 2001:dead::5 is not inside 2001:db8::/32 — different traffic, not shadowed.
  const rs = [
    '# Generated by ip6tables-save',
    '*filter',
    ':INPUT ACCEPT [0:0]',
    '-A INPUT -s 2001:db8::/32 -j DROP',
    '-A INPUT -s 2001:dead::5/128 -j DROP',
    'COMMIT',
  ].join('\n');
  const { findings } = FS.lint(FS.parse(rs));
  assert.ok(!findings.some((f) => f.id === 'shadowed-rule'));
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

test('wide-open-port-range flags a huge dport range but not an ordinary one', () => {
  const { findings } = FS.lint(FS.parse(sample('iptables-exposed-services.txt')));
  const wide = findings.filter((f) => f.id === 'wide-open-port-range');
  // The 1024:65535 rule (64512 ports) is flagged...
  assert.equal(wide.length, 1);
  assert.match(wide[0].title, /64512 ports/);

  // ...but a few-hundred-port app range from any source is not.
  const rs = [
    '*filter', ':INPUT ACCEPT [0:0]',
    '-A INPUT -p tcp -m tcp --dport 8000:8200 -j ACCEPT',
    'COMMIT',
  ].join('\n');
  const ids = new Set(FS.lint(FS.parse(rs)).findings.map((f) => f.id));
  assert.ok(!ids.has('wide-open-port-range'), '201 ports is not "wide"');
});

test('the sample set exercises every smell', () => {
  const seen = new Set();
  for (const name of Object.keys(EXPECTED)) {
    for (const id of lintIds(name)) seen.add(id);
  }
  for (const id of ALL_SMELLS) {
    assert.ok(seen.has(id), `no sample triggers '${id}'`);
  }
});

test('missing-established-accept does NOT fire when the conntrack rule exists', () => {
  const rs = [
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -i lo -j ACCEPT',
    '-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT',
    'COMMIT',
  ].join('\n');
  const ids = new Set(FS.lint(FS.parse(rs)).findings.map((f) => f.id));
  assert.ok(!ids.has('missing-established-accept'));
});

test('missing-established-accept is skipped for ufw (backend adds it invisibly)', () => {
  // Deny posture, no conntrack rule visible — exactly what `ufw status` shows.
  const ids = lintIds('ufw-status.txt');
  assert.ok(!ids.has('missing-established-accept'));
});

test('overbroad-source-trust flags huge public ranges, spares private and honest CIDRs', () => {
  const rs = [
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -s 0.0.0.0/1 -p tcp -m tcp --dport 22 -j ACCEPT',
    '-A INPUT -s 128.0.0.0/2 -p tcp -m tcp --dport 443 -j ACCEPT',
    '-A INPUT -s 10.0.0.0/8 -p tcp -m tcp --dport 22 -j ACCEPT',
    '-A INPUT -s 192.168.1.0/24 -p tcp -m tcp --dport 22 -j ACCEPT',
    '-A INPUT -s 44.0.0.0/9 -p tcp -m tcp --dport 22 -j ACCEPT',
    'COMMIT',
  ].join('\n');
  const hits = FS.lint(FS.parse(rs)).findings.filter((f) => f.id === 'overbroad-source-trust');
  // The /1 and the public /2 are flagged; the private /8, the /24 and the
  // public /9 (just past the threshold) are not.
  assert.equal(hits.length, 2);
  // JSON round-trip: linter arrays come from the vm sandbox (cross-realm).
  assert.equal(JSON.stringify(hits.map((h) => h.ruleIdx)), '[0,1]');
  assert.equal(hits[0].severity, 'warning');
  assert.match(hits[0].title, /0\.0\.0\.0\/1/);
});

test('overbroad-source-trust understands IPv6: global unicast flagged, ULA and link-local spared', () => {
  const rs = [
    '# Generated by ip6tables-save',
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -s 2000::/3 -p tcp -m tcp --dport 22 -j ACCEPT',
    '-A INPUT -s fc00::/7 -p tcp -m tcp --dport 22 -j ACCEPT',
    '-A INPUT -s fe80::/10 -p tcp -m tcp --dport 22 -j ACCEPT',
    '-A INPUT -s 2001:db8::/32 -p tcp -m tcp --dport 22 -j ACCEPT',
    'COMMIT',
  ].join('\n');
  const hits = FS.lint(FS.parse(rs)).findings.filter((f) => f.id === 'overbroad-source-trust');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].ruleIdx, 0, 'only 2000::/3 (all global unicast) is flagged');
});

test('overbroad-source-trust leaves DROP rules and true any-source accepts alone', () => {
  const rs = [
    '*filter', ':INPUT ACCEPT [0:0]',
    '-A INPUT -s 0.0.0.0/1 -j DROP',
    '-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT',
    'COMMIT',
  ].join('\n');
  const ids = new Set(FS.lint(FS.parse(rs)).findings.map((f) => f.id));
  // A broad DROP is caution, not trust; the source-less accept belongs to
  // the any-source smells, not this one.
  assert.ok(!ids.has('overbroad-source-trust'));
});

test('missing-invalid-drop stays quiet when INVALID is dropped before the accepts', () => {
  const rs = [
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -i lo -j ACCEPT',
    '-A INPUT -m conntrack --ctstate INVALID -j DROP',
    '-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT',
    '-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT',
    'COMMIT',
  ].join('\n');
  const ids = new Set(FS.lint(FS.parse(rs)).findings.map((f) => f.id));
  assert.ok(!ids.has('missing-invalid-drop'));
});

test('missing-invalid-drop flags an INVALID drop placed below the accepts', () => {
  const rs = [
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -i lo -j ACCEPT',
    '-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT',
    '-A INPUT -m conntrack --ctstate INVALID -j DROP',
    'COMMIT',
  ].join('\n');
  const hits = FS.lint(FS.parse(rs)).findings.filter((f) => f.id === 'missing-invalid-drop');
  assert.equal(hits.length, 1);
  // Points at the misplaced drop itself (rule index 2), not at the chain.
  assert.equal(hits[0].ruleIdx, 2);
  assert.match(hits[0].title, /after its ACCEPT rules/);
});

test('missing-invalid-drop needs an accept a crafted packet could ride', () => {
  // Deny posture but only loopback + conntrack accepts: nothing to ride, no
  // finding — a chain like this is missing-established-accept's business.
  const rs = [
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -i lo -j ACCEPT',
    '-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT',
    'COMMIT',
  ].join('\n');
  const ids = new Set(FS.lint(FS.parse(rs)).findings.map((f) => f.id));
  assert.ok(!ids.has('missing-invalid-drop'));
});

test('missing-invalid-drop understands the nft spelling and is skipped for ufw', () => {
  const clean = [
    'table inet filter {',
    '  chain input {',
    '    type filter hook input priority 0; policy drop;',
    '    iifname "lo" accept',
    '    ct state invalid drop',
    '    ct state established,related accept',
    '    tcp dport 22 accept',
    '  }',
    '}',
  ].join('\n');
  assert.ok(!new Set(FS.lint(FS.parse(clean)).findings.map((f) => f.id)).has('missing-invalid-drop'));

  const dirty = clean.replace('    ct state invalid drop\n', '');
  assert.ok(new Set(FS.lint(FS.parse(dirty)).findings.map((f) => f.id)).has('missing-invalid-drop'));

  // ufw's backend drops INVALID in ufw-before-input without ever showing it.
  assert.ok(!lintIds('ufw-status.txt').has('missing-invalid-drop'));
});

test('forward-no-default-deny stays quiet on policy DROP or a catch-all tail', () => {
  const dropPolicy = [
    '*filter', ':FORWARD DROP [0:0]', 'COMMIT',
  ].join('\n');
  assert.ok(!new Set(FS.lint(FS.parse(dropPolicy)).findings.map((f) => f.id)).has('forward-no-default-deny'));

  const catchAll = [
    '*filter', ':FORWARD ACCEPT [0:0]',
    '-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT',
    '-A FORWARD -j DROP',
    'COMMIT',
  ].join('\n');
  assert.ok(!new Set(FS.lint(FS.parse(catchAll)).findings.map((f) => f.id)).has('forward-no-default-deny'));
});

test('masquerade-any-source stays quiet when the source is restricted', () => {
  const rs = [
    '*nat', ':POSTROUTING ACCEPT [0:0]',
    '-A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE',
    'COMMIT',
  ].join('\n');
  const ids = new Set(FS.lint(FS.parse(rs)).findings.map((f) => f.id));
  assert.ok(!ids.has('masquerade-any-source'));
});

test('masquerade-any-source flags an unrestricted nft masquerade, not a saddr-scoped one', () => {
  const flagged = [
    'table ip nat {',
    '	chain postrouting {',
    '		type nat hook postrouting priority srcnat; policy accept;',
    '		oifname "eth0" masquerade',
    '	}',
    '}',
  ].join('\n');
  assert.ok(new Set(FS.lint(FS.parse(flagged)).findings.map((f) => f.id)).has('masquerade-any-source'));

  const scoped = [
    'table ip nat {',
    '	chain postrouting {',
    '		type nat hook postrouting priority srcnat; policy accept;',
    '		ip saddr 10.8.0.0/24 oifname "eth0" masquerade',
    '	}',
    '}',
  ].join('\n');
  assert.ok(!new Set(FS.lint(FS.parse(scoped)).findings.map((f) => f.id)).has('masquerade-any-source'));
});

test('drop-without-log stays quiet when a LOG rule exists, and is skipped for ufw', () => {
  const logged = [
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -i lo -j ACCEPT',
    '-A INPUT -m limit --limit 5/min -j LOG --log-prefix "DROP-INPUT: "',
    'COMMIT',
  ].join('\n');
  assert.ok(!new Set(FS.lint(FS.parse(logged)).findings.map((f) => f.id)).has('drop-without-log'));

  // ufw's backend logs on its own; `ufw status` can't show it — never flag.
  assert.ok(!lintIds('ufw-status.txt').has('drop-without-log'));
});

test('drop-without-log recognizes the nft log statement (not just -j LOG)', () => {
  const rs = [
    'table inet filter {',
    '	chain input {',
    '		type filter hook input priority filter; policy drop;',
    '		log prefix "DROP-INPUT: "',
    '	}',
    '}',
  ].join('\n');
  assert.ok(!new Set(FS.lint(FS.parse(rs)).findings.map((f) => f.id)).has('drop-without-log'));
});

test('drop-without-log fires as info on a silent default-deny', () => {
  const rs = [
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -i lo -j ACCEPT',
    'COMMIT',
  ].join('\n');
  const { findings } = FS.lint(FS.parse(rs));
  const f = findings.find((x) => x.id === 'drop-without-log');
  assert.ok(f, 'expected drop-without-log');
  assert.equal(f.severity, 'info');
});

test('icmpv6-blocked stays quiet when ICMPv6 is accepted (even via a jumped chain)', () => {
  // Direct accept — the known-good ip6tables sample has `-p ipv6-icmp -j ACCEPT`.
  assert.ok(!lintIds('ip6tables-save.txt').has('icmpv6-blocked'));

  // Accept behind a user-chain jump must count too.
  const jumped = [
    '# Generated by ip6tables-save',
    '*filter',
    ':INPUT DROP [0:0]',
    ':ICMP6 - [0:0]',
    '-A INPUT -j ICMP6',
    '-A ICMP6 -p ipv6-icmp -j ACCEPT',
    'COMMIT',
  ].join('\n');
  assert.ok(!new Set(FS.lint(FS.parse(jumped)).findings.map((f) => f.id)).has('icmpv6-blocked'));
});

test('icmpv6-blocked never fires on IPv4-only or ufw rulesets', () => {
  // Plain iptables says nothing about the host's IPv6 posture.
  assert.ok(!lintIds('iptables-leaky.txt').has('icmpv6-blocked'));
  assert.ok(!lintIds('iptables-router-sloppy.txt').has('icmpv6-blocked'));
  // ufw's before6.rules accepts ICMPv6 invisibly.
  assert.ok(!lintIds('ufw-status.txt').has('icmpv6-blocked'));
});

test('icmpv6-blocked fires on an nft inet input that drops without an ICMPv6 accept', () => {
  const rs = [
    'table inet filter {',
    '	chain input {',
    '		type filter hook input priority filter; policy drop;',
    '		iifname "lo" accept',
    '		ct state established,related accept',
    '		tcp dport 22 accept',
    '	}',
    '}',
  ].join('\n');
  const { findings } = FS.lint(FS.parse(rs));
  const f = findings.find((x) => x.id === 'icmpv6-blocked');
  assert.ok(f, 'expected icmpv6-blocked');
  assert.equal(f.severity, 'error');
});

test('icmpv6-blocked recognizes the nft `ip6 nexthdr icmpv6` spelling', () => {
  // The flagship nft sample allows ICMPv6 that way — must stay clean.
  assert.ok(!lintIds('nft-ruleset.txt').has('icmpv6-blocked'));

  // An ip-family (IPv4-only) nft table is never flagged.
  const v4only = [
    'table ip filter {',
    '	chain input {',
    '		type filter hook input priority filter; policy drop;',
    '		ct state established,related accept',
    '	}',
    '}',
  ].join('\n');
  assert.ok(!new Set(FS.lint(FS.parse(v4only)).findings.map((f) => f.id)).has('icmpv6-blocked'));
});

test('icmp-pmtud-blocked: rule-level on the icmp DROP before conntrack, chain-level on FORWARD', () => {
  const { findings } = FS.lint(FS.parse(sample('iptables-no-pmtud.txt')));
  const hits = findings.filter((f) => f.id === 'icmp-pmtud-blocked');
  const ruleHit = hits.find((f) => f.chain === 'INPUT');
  assert.ok(ruleHit, 'expected a rule-level hit in INPUT');
  assert.equal(typeof ruleHit.ruleIdx, 'number');
  assert.equal(ruleHit.severity, 'warning');
  const chainHit = hits.find((f) => f.chain === 'FORWARD');
  assert.ok(chainHit, 'expected a chain-level hit in FORWARD');
  assert.equal(chainHit.ruleIdx, null);
});

test('icmp-pmtud-blocked stays quiet when the RELATED accept comes before the icmp drop', () => {
  const rs = [
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT',
    '-A INPUT -p icmp -j DROP',
    '-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT',
    'COMMIT',
  ].join('\n');
  const ids = new Set(FS.lint(FS.parse(rs)).findings.map((f) => f.id));
  assert.ok(!ids.has('icmp-pmtud-blocked'));
});

test('icmp-pmtud-blocked: ESTABLISHED alone is not enough — ICMP errors arrive as RELATED', () => {
  const rs = [
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT',
    '-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT',
    'COMMIT',
  ].join('\n');
  const ids = new Set(FS.lint(FS.parse(rs)).findings.map((f) => f.id));
  assert.ok(ids.has('icmp-pmtud-blocked'));
});

test('icmp-pmtud-blocked spares an echo-request-only drop when type 3 is accepted', () => {
  const rs = [
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -p icmp --icmp-type echo-request -j DROP',
    '-A INPUT -p icmp --icmp-type destination-unreachable -j ACCEPT',
    '-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT',
    'COMMIT',
  ].join('\n');
  const ids = new Set(FS.lint(FS.parse(rs)).findings.map((f) => f.id));
  assert.ok(!ids.has('icmp-pmtud-blocked'));
});

test('icmp-pmtud-blocked: an empty deny-posture FORWARD (non-router) is not a black hole', () => {
  // These flagship/other samples have FORWARD DROP with no accepts — correct
  // config for a non-forwarding host, nothing whose PMTUD could break.
  assert.ok(!lintIds('iptables-save.txt').has('icmp-pmtud-blocked'));
  assert.ok(!lintIds('iptables-shadowed.txt').has('icmp-pmtud-blocked'));
  assert.ok(!lintIds('nft-v4only.txt').has('icmp-pmtud-blocked'));
});

test('icmp-pmtud-blocked never fires on ufw or ip6tables rulesets', () => {
  assert.ok(!lintIds('ufw-status.txt').has('icmp-pmtud-blocked'));
  assert.ok(!lintIds('ip6tables-no-icmpv6.txt').has('icmp-pmtud-blocked'));
  assert.ok(!lintIds('ip6tables-save.txt').has('icmp-pmtud-blocked'));
});

test('icmp-pmtud-blocked on nft: accepting input without icmp/related fires; `ip protocol icmp accept` silences', () => {
  const bare = [
    'table inet filter {',
    '	chain input {',
    '		type filter hook input priority filter; policy drop;',
    '		iifname "lo" accept',
    '		tcp dport 443 accept',
    '	}',
    '}',
  ].join('\n');
  const ids = new Set(FS.lint(FS.parse(bare)).findings.map((f) => f.id));
  assert.ok(ids.has('icmp-pmtud-blocked'));
  // The flagship nft samples accept ICMP via `ip protocol icmp ... accept`.
  assert.ok(!lintIds('nft-ruleset.txt').has('icmp-pmtud-blocked'));
  assert.ok(!lintIds('nft-v4only.txt').has('icmp-pmtud-blocked'));
});

test('unused-chain is a warning with rules, info when empty, quiet when referenced', () => {
  const rs = [
    '*filter',
    ':INPUT DROP [0:0]',
    ':WIRED - [0:0]',
    ':ORPHAN - [0:0]',
    ':EMPTY - [0:0]',
    '-A INPUT -j WIRED',
    '-A WIRED -p tcp --dport 443 -j ACCEPT',
    '-A ORPHAN -s 192.168.0.0/16 -j ACCEPT',
    'COMMIT',
  ].join('\n');
  const { findings } = FS.lint(FS.parse(rs));
  const unused = findings.filter((f) => f.id === 'unused-chain');
  // JSON compare: the linter runs in a vm sandbox, so its arrays have a
  // different Array.prototype and deepStrictEqual rejects them cross-realm.
  assert.equal(
    JSON.stringify(unused.map((f) => [f.chain, f.severity]).sort()),
    JSON.stringify([['EMPTY', 'info'], ['ORPHAN', 'warning']]),
  );
});

test('unused-chain flags a chain referenced only by another dead chain', () => {
  const rs = [
    '*filter',
    ':INPUT DROP [0:0]',
    ':DEAD_A - [0:0]',
    ':DEAD_B - [0:0]',
    '-A DEAD_A -j DEAD_B',
    '-A DEAD_B -j ACCEPT',
    'COMMIT',
  ].join('\n');
  const { findings } = FS.lint(FS.parse(rs));
  const unused = findings.filter((f) => f.id === 'unused-chain').map((f) => f.chain).sort();
  assert.equal(JSON.stringify(unused), JSON.stringify(['DEAD_A', 'DEAD_B']));
});

test('unused-chain stays quiet on the flagship samples (all chains wired)', () => {
  assert.ok(!lintIds('iptables-save.txt').has('unused-chain'));
  assert.ok(!lintIds('nft-ruleset.txt').has('unused-chain'));
  assert.ok(!lintIds('ufw-status.txt').has('unused-chain'));
});

test('unused-chain works for nftables chains without a hook', () => {
  const rs = [
    'table inet filter {',
    '	chain input {',
    '		type filter hook input priority filter; policy drop;',
    '		jump wired',
    '	}',
    '	chain wired {',
    '		tcp dport 22 accept',
    '	}',
    '	chain orphan {',
    '		tcp dport 8080 accept',
    '	}',
    '}',
  ].join('\n');
  const { findings } = FS.lint(FS.parse(rs));
  const unused = findings.filter((f) => f.id === 'unused-chain');
  assert.equal(unused.length, 1);
  assert.equal(unused[0].chain, 'orphan');
});

test('unlimited-log fires on an unthrottled LOG, quiet with -m limit / hashlimit', () => {
  const bare = [
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -j LOG --log-prefix "IN: "',
    'COMMIT',
  ].join('\n');
  const { findings } = FS.lint(FS.parse(bare));
  const hit = findings.find((f) => f.id === 'unlimited-log');
  assert.ok(hit, 'expected unlimited-log');
  assert.equal(hit.severity, 'warning');
  assert.equal(hit.ruleIdx, 0);

  for (const limited of [
    '-A INPUT -m limit --limit 5/min -j LOG --log-prefix "IN: "',
    '-A INPUT -m hashlimit --hashlimit-above 10/min --hashlimit-name lg -j LOG',
  ]) {
    const rs = ['*filter', ':INPUT DROP [0:0]', limited, 'COMMIT'].join('\n');
    const ids = new Set(FS.lint(FS.parse(rs)).findings.map((f) => f.id));
    assert.ok(!ids.has('unlimited-log'), `should be quiet for: ${limited}`);
  }
});

test('unlimited-log understands the nft limit rate statement', () => {
  const flagged = [
    'table inet filter {',
    '	chain input {',
    '		type filter hook input priority filter; policy drop;',
    '		log prefix "IN: "',
    '	}',
    '}',
  ].join('\n');
  assert.ok(new Set(FS.lint(FS.parse(flagged)).findings.map((f) => f.id)).has('unlimited-log'));

  const throttled = [
    'table inet filter {',
    '	chain input {',
    '		type filter hook input priority filter; policy drop;',
    '		limit rate 5/minute log prefix "IN: "',
    '	}',
    '}',
  ].join('\n');
  assert.ok(!new Set(FS.lint(FS.parse(throttled)).findings.map((f) => f.id)).has('unlimited-log'));
});

test('unlimited-log stays quiet on the flagship samples (their LOGs are throttled)', () => {
  for (const s of ['iptables-save.txt', 'ip6tables-save.txt', 'nft-ruleset.txt', 'ufw-status.txt']) {
    assert.ok(!lintIds(s).has('unlimited-log'), `expected ${s} clean`);
  }
});

test('duplicate-rule flags the copy, points at the original, and skips near-duplicates', () => {
  const rs = [
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -m limit --limit 5/min -j LOG --log-prefix "IN: "',
    '-A INPUT -p tcp -m tcp --dport 22 -s 10.0.0.0/8 -j ACCEPT',
    '-A INPUT -m limit --limit 5/min -j LOG --log-prefix "IN: "',
    '-A INPUT -p tcp -m tcp --dport 22 -s 10.0.1.0/24 -j ACCEPT',
    'COMMIT',
  ].join('\n');
  const { findings } = FS.lint(FS.parse(rs));
  const dups = findings.filter((f) => f.id === 'duplicate-rule');
  assert.equal(dups.length, 1, 'only the byte-identical LOG copy is a duplicate');
  assert.equal(dups[0].ruleIdx, 2);
  assert.equal(dups[0].duplicateOf, 0);
  assert.equal(dups[0].severity, 'warning');
});

test('an exact terminal copy is duplicate-rule, not shadowed-rule; a subset is still shadowed-rule', () => {
  const rs = [
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT',
    '-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT',
    '-A INPUT -p tcp -m tcp --dport 22 -s 10.0.0.0/8 -j ACCEPT',
    'COMMIT',
  ].join('\n');
  const { findings } = FS.lint(FS.parse(rs));
  const dup = findings.filter((f) => f.id === 'duplicate-rule');
  const shadowed = findings.filter((f) => f.id === 'shadowed-rule');
  assert.equal(dup.length, 1);
  assert.equal(dup[0].ruleIdx, 1);
  assert.equal(shadowed.length, 1, 'the narrower rule is shadowing, not duplication');
  assert.equal(shadowed[0].ruleIdx, 2);
});

test('duplicate-rule understands nft rulesets and ignores whitespace differences', () => {
  const rs = [
    'table inet filter {',
    '	chain input {',
    '		type filter hook input priority filter; policy drop;',
    '		limit rate 5/minute log prefix "IN: "',
    '		limit rate 5/minute  log prefix "IN: "',
    '	}',
    '}',
  ].join('\n');
  const { findings } = FS.lint(FS.parse(rs));
  assert.ok(findings.some((f) => f.id === 'duplicate-rule'));
});

test('duplicate-rule stays quiet on the flagship samples', () => {
  for (const s of ['iptables-save.txt', 'ip6tables-save.txt', 'nft-ruleset.txt', 'ufw-status.txt', 'iptables-shadowed.txt']) {
    assert.ok(!lintIds(s).has('duplicate-rule'), `expected ${s} clean`);
  }
});

test('nft forward hook with policy accept is flagged too', () => {
  const rs = [
    'table inet filter {',
    '	chain forward {',
    '		type filter hook forward priority filter; policy accept;',
    '	}',
    '}',
  ].join('\n');
  const { findings } = FS.lint(FS.parse(rs));
  assert.ok(findings.some((f) => f.id === 'forward-no-default-deny'));
});

test('unlimited-icmp-echo flags blanket and explicit v4 echo accepts, spares limited/typed/scoped ones', () => {
  const rs = [
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -p icmp -j ACCEPT',
    '-A INPUT -p icmp -m icmp --icmp-type echo-request -j ACCEPT',
    '-A INPUT -p icmp -m limit --limit 10/sec -j ACCEPT',
    '-A INPUT -p icmp -m icmp --icmp-type destination-unreachable -j ACCEPT',
    '-A INPUT -p icmp -s 10.0.0.0/8 -j ACCEPT',
    'COMMIT',
  ].join('\n');
  const hits = FS.lint(FS.parse(rs)).findings.filter((f) => f.id === 'unlimited-icmp-echo');
  // Blanket icmp (echo included) and explicit echo-request fire; the
  // rate-limited, non-echo-typed and source-scoped accepts do not.
  assert.equal(JSON.stringify(hits.map((h) => h.ruleIdx)), JSON.stringify([0, 1]));
  assert.equal(hits[0].severity, 'info');
});

test('unlimited-icmp-echo reads the nft spellings and respects limit rate', () => {
  const rs = [
    'table inet filter {',
    '	chain input {',
    '		type filter hook input priority 0; policy drop;',
    '		icmp type echo-request accept',
    '		ip protocol icmp limit rate 10/second accept',
    '	}',
    '}',
  ].join('\n');
  const hits = FS.lint(FS.parse(rs)).findings.filter((f) => f.id === 'unlimited-icmp-echo');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].ruleIdx, 0);
});

test('unlimited-icmp-echo punishes explicit ICMPv6 echo but never blanket ICMPv6', () => {
  // Blanket ICMPv6 accepts are what icmpv6-blocked demands (Neighbor
  // Discovery, PMTUD) — only an explicit unthrottled echo-request match
  // (type 128) is ping-specific enough to flag.
  const rs = [
    '# Generated by ip6tables-save',
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -p ipv6-icmp -j ACCEPT',
    '-A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 128 -j ACCEPT',
    '-A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type echo-request -m limit --limit 5/sec -j ACCEPT',
    'COMMIT',
  ].join('\n');
  const hits = FS.lint(FS.parse(rs)).findings.filter((f) => f.id === 'unlimited-icmp-echo');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].ruleIdx, 1);
});

test('unlimited-icmp-echo is skipped for ufw', () => {
  const ids = lintIds('ufw-status.txt');
  assert.ok(!ids.has('unlimited-icmp-echo'));
});

test('unrestricted-egress fires when INPUT is locked down and OUTPUT is wide open', () => {
  const rs = [
    '*filter',
    ':INPUT DROP [0:0]',
    ':OUTPUT ACCEPT [0:0]',
    '-A INPUT -i lo -j ACCEPT',
    'COMMIT',
  ].join('\n');
  const hits = FS.lint(FS.parse(rs)).findings.filter((f) => f.id === 'unrestricted-egress');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].severity, 'info');
  assert.equal(hits[0].chain, 'OUTPUT');
  assert.equal(hits[0].ruleIdx, null);
});

test('unrestricted-egress stays quiet when INPUT is open too (missing-input-drop territory)', () => {
  const rs = [
    '*filter',
    ':INPUT ACCEPT [0:0]',
    ':OUTPUT ACCEPT [0:0]',
    'COMMIT',
  ].join('\n');
  const ids = new Set(FS.lint(FS.parse(rs)).findings.map((f) => f.id));
  assert.ok(!ids.has('unrestricted-egress'));
  assert.ok(ids.has('missing-input-drop'));
});

test('unrestricted-egress spares an OUTPUT with deny policy or a catch-all deny', () => {
  const policyDeny = [
    '*filter',
    ':INPUT DROP [0:0]',
    ':OUTPUT DROP [0:0]',
    '-A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT',
    'COMMIT',
  ].join('\n');
  assert.ok(!new Set(FS.lint(FS.parse(policyDeny)).findings.map((f) => f.id)).has('unrestricted-egress'));

  const catchAll = [
    '*filter',
    ':INPUT DROP [0:0]',
    ':OUTPUT ACCEPT [0:0]',
    '-A OUTPUT -p udp --dport 53 -j ACCEPT',
    '-A OUTPUT -j DROP',
    'COMMIT',
  ].join('\n');
  assert.ok(!new Set(FS.lint(FS.parse(catchAll)).findings.map((f) => f.id)).has('unrestricted-egress'));
});

test('unrestricted-egress accepts a catch-all-drop INPUT as "locked down"', () => {
  // Deny posture via final catch-all rule instead of chain policy.
  const rs = [
    '*filter',
    ':INPUT ACCEPT [0:0]',
    ':OUTPUT ACCEPT [0:0]',
    '-A INPUT -i lo -j ACCEPT',
    '-A INPUT -j DROP',
    'COMMIT',
  ].join('\n');
  const hits = FS.lint(FS.parse(rs)).findings.filter((f) => f.id === 'unrestricted-egress');
  assert.equal(hits.length, 1);
});

test('unrestricted-egress reads the nft hooks and spares a deny-posture output', () => {
  const open = [
    'table inet filter {',
    '	chain input {',
    '		type filter hook input priority 0; policy drop;',
    '	}',
    '	chain output {',
    '		type filter hook output priority 0; policy accept;',
    '	}',
    '}',
  ].join('\n');
  const hits = FS.lint(FS.parse(open)).findings.filter((f) => f.id === 'unrestricted-egress');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].chain, 'output');

  const filtered = open.replace('hook output priority 0; policy accept;', 'hook output priority 0; policy drop;');
  assert.ok(!new Set(FS.lint(FS.parse(filtered)).findings.map((f) => f.id)).has('unrestricted-egress'));
});

test('unrestricted-egress fires on the default ufw posture (deny in, allow out)', () => {
  const hits = FS.lint(FS.parse(sample('ufw-status.txt'))).findings.filter((f) => f.id === 'unrestricted-egress');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].chain, 'OUTPUT');
});

test('mac-based-trust flags an ACCEPT keyed on a source MAC, spares a DROP', () => {
  const rs = [
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -p tcp -m tcp --dport 8080 -m mac --mac-source AA:BB:CC:DD:EE:FF -j ACCEPT',
    '-A INPUT -m mac --mac-source 11:22:33:44:55:66 -j DROP',
    'COMMIT',
  ].join('\n');
  const hits = FS.lint(FS.parse(rs)).findings.filter((f) => f.id === 'mac-based-trust');
  // The trusting ACCEPT fires; blocking a known-bad MAC is caution, not trust.
  assert.equal(hits.length, 1);
  assert.equal(hits[0].ruleIdx, 0);
  assert.equal(hits[0].severity, 'warning');
  assert.match(hits[0].title, /AA:BB:CC:DD:EE:FF/);
});

test('mac-based-trust reads the nft ether saddr spelling', () => {
  const rs = [
    'table inet filter {',
    '	chain input {',
    '		type filter hook input priority 0; policy drop;',
    '		ether saddr aa:bb:cc:dd:ee:ff tcp dport 8080 accept',
    '		ether saddr 11:22:33:44:55:66 drop',
    '	}',
    '}',
  ].join('\n');
  const hits = FS.lint(FS.parse(rs)).findings.filter((f) => f.id === 'mac-based-trust');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].ruleIdx, 0);
});

test('mac-based-trust does not double-count and coexists with the IP-level smells', () => {
  // An ssh accept "restricted" by MAC only: exposed-admin-port must STILL
  // fire (a MAC match is not a source restriction) alongside this smell.
  const rs = [
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -p tcp -m tcp --dport 22 -m mac --mac-source AA:BB:CC:DD:EE:FF -j ACCEPT',
    'COMMIT',
  ].join('\n');
  const ids = FS.lint(FS.parse(rs)).findings.map((f) => f.id);
  assert.equal(ids.filter((x) => x === 'mac-based-trust').length, 1);
  assert.ok(ids.includes('exposed-admin-port'), 'MAC match must not count as a source restriction');
});

test('source-port-trust flags an inbound ACCEPT keyed on sport, spares a DROP', () => {
  const rs = [
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -p udp -m udp --sport 53 -j ACCEPT',
    '-A INPUT -p udp -m udp --sport 67 -j DROP',
    'COMMIT',
  ].join('\n');
  const hits = FS.lint(FS.parse(rs)).findings.filter((f) => f.id === 'source-port-trust');
  // The trusting ACCEPT fires; blocking by sport is caution, not trust.
  assert.equal(hits.length, 1);
  assert.equal(hits[0].ruleIdx, 0);
  assert.equal(hits[0].severity, 'warning');
  assert.match(hits[0].title, /53/);
});

test('source-port-trust spares a dport-pinned rule and an ESTABLISHED-gated one', () => {
  const rs = [
    '*filter', ':INPUT DROP [0:0]',
    // dport pinned: the service scopes the accept, sport is decoration.
    '-A INPUT -p udp -m udp --sport 123 --dport 123 -j ACCEPT',
    // conntrack is the gate, not the sport.
    '-A INPUT -p udp -m udp --sport 53 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT',
    'COMMIT',
  ].join('\n');
  const ids = FS.lint(FS.parse(rs)).findings.map((f) => f.id);
  assert.ok(!ids.includes('source-port-trust'));
});

test('source-port-trust judges only the inbound side: OUTPUT is exempt, a chain jumped from INPUT is not', () => {
  const rs = [
    '*filter', ':INPUT DROP [0:0]', ':OUTPUT DROP [0:0]', ':REPLIES - [0:0]',
    // Stateless egress: matching the host's OWN sport is legitimate.
    '-A OUTPUT -p tcp -m tcp --sport 22 -j ACCEPT',
    // Same match reached from INPUT via a user chain: that is the smell.
    '-A INPUT -j REPLIES',
    '-A REPLIES -p udp -m udp --sport 53 -j ACCEPT',
    'COMMIT',
  ].join('\n');
  const hits = FS.lint(FS.parse(rs)).findings.filter((f) => f.id === 'source-port-trust');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].chain, 'REPLIES');
});

test('source-port-trust reads the nft sport spelling', () => {
  const rs = [
    'table inet filter {',
    '	chain input {',
    '		type filter hook input priority 0; policy drop;',
    '		udp sport 53 accept',
    '	}',
    '	chain output {',
    '		type filter hook output priority 0; policy drop;',
    '		tcp sport 22 accept',
    '	}',
    '}',
  ].join('\n');
  const hits = FS.lint(FS.parse(rs)).findings.filter((f) => f.id === 'source-port-trust');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].chain, 'input');
});

test('admin-port-no-rate-limit flags an unthrottled SSH accept, spares a throttled one', () => {
  const rs = [
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT',
    '-A INPUT -p tcp --dport 22 -m recent --set -j ACCEPT',
    '-A INPUT -p tcp --dport 22 -m hashlimit --hashlimit-name ssh --hashlimit-above 5/min -j ACCEPT',
    '-A INPUT -p tcp --dport 22 -m connlimit --connlimit-above 10 -j DROP',
    'COMMIT',
  ].join('\n');
  const hits = FS.lint(FS.parse(rs)).findings.filter((f) => f.id === 'admin-port-no-rate-limit');
  // Only the first (bare) accept is flagged; recent/hashlimit ones are throttled,
  // and the connlimit rule is a DROP (not an accept) so it never qualifies.
  assert.equal(hits.length, 1);
  assert.equal(hits[0].ruleIdx, 0);
  assert.equal(hits[0].severity, 'info');
  assert.match(hits[0].title, /ssh/);
});

test('admin-port-no-rate-limit ignores non-admin service ports', () => {
  const rs = [
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT',
    '-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT',
    'COMMIT',
  ].join('\n');
  const ids = new Set(FS.lint(FS.parse(rs)).findings.map((f) => f.id));
  assert.ok(!ids.has('admin-port-no-rate-limit'), 'http/https are not admin ports');
});

test('admin-port-no-rate-limit reads the nft limit rate / ct count spellings', () => {
  const rs = [
    'table inet filter {',
    '	chain input {',
    '		type filter hook input priority 0; policy drop;',
    '		tcp dport 3389 accept',
    '		tcp dport 3306 limit rate 10/minute accept',
    '		tcp dport 5432 ct count over 20 drop',
    '	}',
    '}',
  ].join('\n');
  const hits = FS.lint(FS.parse(rs)).findings.filter((f) => f.id === 'admin-port-no-rate-limit');
  // rdp/3389 bare accept fires; the throttled mysql accept and the ct-count
  // postgres drop do not.
  assert.equal(hits.length, 1);
  assert.equal(hits[0].ruleIdx, 0);
  assert.match(hits[0].title, /rdp/);
});

test('admin-port-no-rate-limit composes with exposed-admin-port (different axes)', () => {
  // An any-source SSH with no throttle: exposed-admin-port (who) AND
  // admin-port-no-rate-limit (how fast) both fire, once each.
  const rs = [
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT',
    'COMMIT',
  ].join('\n');
  const ids = FS.lint(FS.parse(rs)).findings.map((f) => f.id);
  assert.equal(ids.filter((x) => x === 'admin-port-no-rate-limit').length, 1);
  assert.ok(ids.includes('exposed-admin-port'));
});

test('admin-port-no-rate-limit is skipped for ufw', () => {
  assert.ok(!lintIds('ufw-status.txt').has('admin-port-no-rate-limit'));
});

test('rate-limit-not-per-source flags -m limit on a TCP accept, spares per-source throttles', () => {
  const rs = [
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -p tcp -m tcp --dport 22 -m limit --limit 3/min -j ACCEPT',
    '-A INPUT -p tcp --dport 22 -m recent --update --seconds 60 --hitcount 4 -j ACCEPT',
    '-A INPUT -p tcp --dport 22 -m connlimit --connlimit-above 10 -j ACCEPT',
    '-A INPUT -p tcp --dport 22 -m hashlimit --hashlimit-name ssh --hashlimit-upto 5/min --hashlimit-mode srcip -j ACCEPT',
    'COMMIT',
  ].join('\n');
  const hits = FS.lint(FS.parse(rs)).findings.filter((f) => f.id === 'rate-limit-not-per-source');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].ruleIdx, 0);
  assert.equal(hits[0].severity, 'warning');
});

test('rate-limit-not-per-source flags hashlimit only when its mode lacks srcip', () => {
  const rs = [
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -p tcp --dport 443 -m hashlimit --hashlimit-name web --hashlimit-upto 50/sec -j ACCEPT',
    '-A INPUT -p tcp --dport 443 -m hashlimit --hashlimit-name web2 --hashlimit-upto 50/sec --hashlimit-mode dstport -j ACCEPT',
    '-A INPUT -p tcp --dport 443 -m hashlimit --hashlimit-name web3 --hashlimit-upto 50/sec --hashlimit-mode srcip,dstport -j ACCEPT',
    'COMMIT',
  ].join('\n');
  const hits = FS.lint(FS.parse(rs)).findings.filter((f) => f.id === 'rate-limit-not-per-source');
  // No mode at all and a srcip-less mode are both one shared bucket;
  // srcip,dstport keys per client and stays quiet.
  assert.equal(hits.length, 2);
  // vm-realm arrays fail deepEqual on prototype — compare via JSON.
  assert.equal(JSON.stringify(hits.map((h) => h.ruleIdx).sort()), '[0,1]');
});

test('rate-limit-not-per-source is mutually exclusive with admin-port-no-rate-limit', () => {
  // One SSH accept with a shared throttle, one with none: each rule draws
  // exactly one of the pair — the axes never double-report a rule.
  const rs = [
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -p tcp --dport 22 -m limit --limit 3/min -j ACCEPT',
    '-A INPUT -p tcp --dport 2222 -j ACCEPT',
    '-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT',
    'COMMIT',
  ].join('\n');
  const { findings } = FS.lint(FS.parse(rs));
  const shared = findings.filter((f) => f.id === 'rate-limit-not-per-source');
  const norate = findings.filter((f) => f.id === 'admin-port-no-rate-limit');
  assert.equal(shared.length, 1);
  assert.equal(shared[0].ruleIdx, 0);
  assert.equal(norate.length, 1);
  assert.equal(norate[0].ruleIdx, 2);
});

test('rate-limit-not-per-source leaves ICMP and UDP global caps alone', () => {
  // Our own smells prescribe a global cap for ping (unlimited-icmp-echo),
  // and a UDP ceiling is a legitimate amplification defence — only TCP
  // service accepts are judged.
  const rs = [
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -p icmp --icmp-type echo-request -m limit --limit 10/sec -j ACCEPT',
    '-A INPUT -p udp --dport 53 -m limit --limit 100/sec -j ACCEPT',
    '-A INPUT -p tcp --dport 25 -m limit --limit 10/min -j DROP',
    'COMMIT',
  ].join('\n');
  const ids = new Set(FS.lint(FS.parse(rs)).findings.map((f) => f.id));
  assert.ok(!ids.has('rate-limit-not-per-source'));
});

test('rate-limit-not-per-source reads nft: bare limit rate fires, a saddr meter does not', () => {
  const rs = [
    'table inet filter {',
    '	chain input {',
    '		type filter hook input priority 0; policy drop;',
    '		tcp dport 22 limit rate 3/minute accept',
    '		tcp dport 2222 meter sshmeter { ip saddr limit rate 3/minute } accept',
    '		tcp dport 8080 ct count over 20 accept',
    '	}',
    '}',
  ].join('\n');
  const hits = FS.lint(FS.parse(rs)).findings.filter((f) => f.id === 'rate-limit-not-per-source');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].ruleIdx, 0);
});

test('rate-limit-not-per-source is skipped for ufw (its limit verb is per-source -m recent)', () => {
  assert.ok(!lintIds('ufw-status.txt').has('rate-limit-not-per-source'));
});

test('rate-limit-drop-inverted flags -m limit on a DROP, spares ACCEPT / LOG / the RETURN recipe', () => {
  const rs = [
    '*filter', ':INPUT DROP [0:0]', ':SYNFLOOD - [0:0]',
    '-A INPUT -p tcp -m tcp --dport 80 --tcp-flags FIN,SYN,RST,ACK SYN -m limit --limit 25/sec -j DROP',
    '-A INPUT -p tcp --dport 22 -m limit --limit 3/min -j ACCEPT',
    '-A INPUT -m limit --limit 5/min -j LOG --log-prefix "DROP: "',
    '-A SYNFLOOD -m limit --limit 1/sec --limit-burst 3 -j RETURN',
    '-A SYNFLOOD -j DROP',
    'COMMIT',
  ].join('\n');
  const { findings } = FS.lint(FS.parse(rs));
  const inverted = findings.filter((f) => f.id === 'rate-limit-drop-inverted');
  // Only the direct limit+DROP is backwards; the ACCEPT form and the
  // RETURN-then-DROP recipe are the correct spellings of the same intent.
  assert.equal(inverted.length, 1);
  assert.equal(inverted[0].chain, 'INPUT');
  assert.equal(inverted[0].ruleIdx, 0);
  assert.equal(inverted[0].severity, 'warning');
});

test('rate-limit-drop-inverted fires for any protocol and is mutually exclusive with not-per-source', () => {
  const rs = [
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -p icmp -m limit --limit 10/sec -j DROP',
    'COMMIT',
  ].join('\n');
  const ids = FS.lint(FS.parse(rs)).findings.map((f) => f.id);
  // The inversion is wrong regardless of protocol (this drops calm pings,
  // passes a ping flood); the shared-bucket smell stays TCP-scoped.
  assert.ok(ids.includes('rate-limit-drop-inverted'));
  assert.ok(!ids.includes('rate-limit-not-per-source'));
});

test('rate-limited REJECT is the reflector-avoidance recipe and stays unflagged', () => {
  const rs = [
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -p tcp --dport 113 -m limit --limit 5/sec -j REJECT --reject-with tcp-reset',
    'COMMIT',
  ].join('\n');
  const ids = new Set(FS.lint(FS.parse(rs)).findings.map((f) => f.id));
  // Capping how many polite rejections leave per second (excess falls to a
  // silent drop) is deliberate cost control, not an inverted throttle.
  assert.ok(!ids.has('rate-limit-drop-inverted'));
  assert.ok(!ids.has('rate-limit-not-per-source'));
});

test('drop-the-excess judged by direction: hashlimit-above shared fires not-per-source, srcip is clean', () => {
  const rs = [
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -p tcp --dport 443 -m hashlimit --hashlimit-name a --hashlimit-upto 50/sec -j DROP',
    '-A INPUT -p tcp --dport 443 -m hashlimit --hashlimit-name b --hashlimit-above 50/sec -j DROP',
    '-A INPUT -p tcp --dport 443 -m hashlimit --hashlimit-name c --hashlimit-above 50/sec --hashlimit-mode srcip -j DROP',
    'COMMIT',
  ].join('\n');
  const { findings } = FS.lint(FS.parse(rs));
  const inverted = findings.filter((f) => f.id === 'rate-limit-drop-inverted');
  const shared = findings.filter((f) => f.id === 'rate-limit-not-per-source');
  // upto+DROP = bucket backwards; above without srcip = right direction,
  // one global bucket; above+srcip = the correct per-source flood drop.
  assert.equal(inverted.length, 1);
  assert.equal(inverted[0].ruleIdx, 0);
  assert.equal(shared.length, 1);
  assert.equal(shared[0].ruleIdx, 1);
});

test('rate-limited drops read nft: direction and keying decide, braces do not save an inverted meter', () => {
  const rs = [
    'table inet filter {',
    '	chain input {',
    '		type filter hook input priority 0; policy drop;',
    '		tcp dport 22 limit rate 3/minute drop',
    '		tcp dport 80 limit rate over 200/second drop',
    '		tcp dport 443 meter flood { ip saddr limit rate over 25/second } drop',
    '		udp dport 53 limit rate over 100/second drop',
    '		tcp dport 8443 meter m2 { ip saddr limit rate 3/minute } drop',
    '	}',
    '}',
  ].join('\n');
  const { findings } = FS.lint(FS.parse(rs));
  const inverted = findings.filter((f) => f.id === 'rate-limit-drop-inverted');
  const shared = findings.filter((f) => f.id === 'rate-limit-not-per-source');
  // No `over` = drops the calm traffic — even keyed per source (a meter
  // just inverts per client). `over` bare = right direction, shared bucket
  // (TCP only: the UDP ceiling is a legitimate amplification cap). The
  // saddr meter with `over` is the correct spelling and stays clean.
  assert.equal(JSON.stringify(inverted.map((f) => f.ruleIdx).sort()), '[0,4]');
  assert.equal(shared.length, 1);
  assert.equal(shared[0].ruleIdx, 1);
});

test('rate-limit-drop-inverted is skipped for ufw', () => {
  assert.ok(!lintIds('ufw-status.txt').has('rate-limit-drop-inverted'));
});

test('rate-limit-accept-inverted: an over-limit ACCEPT fires — per-source keying and protocol do not save it', () => {
  // Per-source and non-TCP on purpose: the verdict is the bug, not the
  // keying, so unlike not-per-source neither srcip nor ICMP exempts it.
  const rs = [
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -p icmp -m hashlimit --hashlimit-above 5/sec --hashlimit-mode srcip --hashlimit-name ping -j ACCEPT',
    'COMMIT',
  ].join('\n');
  const hits = FS.lint(FS.parse(rs)).findings.filter((f) => f.id === 'rate-limit-accept-inverted');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].severity, 'warning');
});

test('rate-limit-accept-inverted recognizes the nft spellings, meter included', () => {
  const bare = [
    'table inet filter {',
    '	chain input {',
    '		type filter hook input priority filter; policy drop;',
    '		tcp dport 25 limit rate over 10/second accept',
    '	}',
    '}',
  ].join('\n');
  assert.ok(new Set(FS.lint(FS.parse(bare)).findings.map((f) => f.id)).has('rate-limit-accept-inverted'));
  // A per-client meter just inverts per client.
  const meter = [
    'table inet filter {',
    '	chain input {',
    '		type filter hook input priority filter; policy drop;',
    '		meter guard { ip saddr limit rate over 3/minute } accept',
    '	}',
    '}',
  ].join('\n');
  assert.ok(new Set(FS.lint(FS.parse(meter)).findings.map((f) => f.id)).has('rate-limit-accept-inverted'));
});

test('rate-limit-accept-inverted stays quiet on the three correct quadrants', () => {
  const mk = (line) => new Set(FS.lint(FS.parse(['*filter', ':INPUT DROP [0:0]', line, 'COMMIT'].join('\n'))).findings.map((f) => f.id));
  // Under-limit ACCEPT is the correct throttle direction (not-per-source's
  // beat if the bucket is shared — but never this smell's).
  assert.ok(!mk('-A INPUT -p tcp --dport 22 -m limit --limit 3/min -j ACCEPT').has('rate-limit-accept-inverted'));
  // Over-limit DROP is the correct drop-the-excess recipe.
  assert.ok(!mk('-A INPUT -p tcp --dport 80 -m hashlimit --hashlimit-above 25/sec --hashlimit-mode srcip --hashlimit-name f -j DROP').has('rate-limit-accept-inverted'));
  // Under-limit DROP belongs to the DROP sibling.
  assert.ok(!mk('-A INPUT -p tcp --dport 80 -m limit --limit 25/sec -j DROP').has('rate-limit-accept-inverted'));
});

test('the rate-limit smells stay mutually exclusive: an over-limit ACCEPT never lands in not-per-source', () => {
  // Shared bucket + TCP — exactly what not-per-source judges — but the
  // verdict is inverted, so accept-inverted claims it alone: prescribing
  // srcip keying would "fix" a rule whose real problem is the ACCEPT.
  const rs = [
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -p tcp --dport 25 -m hashlimit --hashlimit-above 10/sec --hashlimit-name smtp -j ACCEPT',
    'COMMIT',
  ].join('\n');
  const ids = new Set(FS.lint(FS.parse(rs)).findings.map((f) => f.id));
  assert.ok(ids.has('rate-limit-accept-inverted'));
  assert.ok(!ids.has('rate-limit-not-per-source'));
  assert.ok(!ids.has('rate-limit-drop-inverted'));
});

test('rate-limit-accept-inverted is skipped for ufw', () => {
  assert.ok(!lintIds('ufw-status.txt').has('rate-limit-accept-inverted'));
});

test('log-tcp-sequence flags the sequence flag, spares plain LOG and --log-tcp-options', () => {
  const rs = [
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -m limit --limit 5/min -j LOG --log-prefix "DROP: " --log-tcp-sequence',
    '-A INPUT -m limit --limit 5/min -j LOG --log-prefix "DROP: "',
    '-A INPUT -m limit --limit 5/min -j LOG --log-prefix "DROP: " --log-tcp-options',
    'COMMIT',
  ].join('\n');
  const hits = FS.lint(FS.parse(rs)).findings.filter((f) => f.id === 'log-tcp-sequence');
  // Only the sequence flag leaks hijacking material; header options do not.
  assert.equal(hits.length, 1);
  assert.equal(hits[0].ruleIdx, 0);
  assert.equal(hits[0].severity, 'warning');
});

test('log-tcp-sequence is independent of unlimited-log (rate-limited but leaking)', () => {
  const rs = [
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -m limit --limit 5/min -j LOG --log-tcp-sequence',
    'COMMIT',
  ].join('\n');
  const ids = FS.lint(FS.parse(rs)).findings.map((f) => f.id);
  assert.ok(ids.includes('log-tcp-sequence'), 'sequence leak fires');
  assert.ok(!ids.includes('unlimited-log'), 'the limit match keeps unlimited-log quiet');
});

test('log-tcp-sequence reads the nft flags spellings, including `flags all`', () => {
  const rs = [
    'table inet filter {',
    '	chain input {',
    '		type filter hook input priority 0; policy drop;',
    '		limit rate 5/minute log flags tcp sequence,options prefix "SEQ: "',
    '		limit rate 5/minute log flags all prefix "ALL: "',
    '		limit rate 5/minute log prefix "PLAIN: "',
    '	}',
    '}',
  ].join('\n');
  const hits = FS.lint(FS.parse(rs)).findings.filter((f) => f.id === 'log-tcp-sequence');
  assert.equal(hits.length, 2);
  assert.equal(JSON.stringify(hits.map((h) => h.ruleIdx)), JSON.stringify([0, 1]));
});

test('log-tcp-sequence is skipped for ufw', () => {
  assert.ok(!lintIds('ufw-status.txt').has('log-tcp-sequence'));
});

test('missing-loopback-spoof-drop fires on a lo-accepting chain with no spoof drop', () => {
  const rs = [
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -i lo -j ACCEPT',
    '-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT',
    'COMMIT',
  ].join('\n');
  const hits = FS.lint(FS.parse(rs)).findings.filter((f) => f.id === 'missing-loopback-spoof-drop');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].severity, 'info');
  assert.equal(hits[0].ruleIdx, null);
});

test('missing-loopback-spoof-drop is satisfied by an early 127.0.0.0/8 drop', () => {
  const rs = [
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -i lo -j ACCEPT',
    '-A INPUT -s 127.0.0.0/8 -j DROP',
    '-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT',
    'COMMIT',
  ].join('\n');
  assert.ok(!FS.lint(FS.parse(rs)).findings.some((f) => f.id === 'missing-loopback-spoof-drop'));
});

test('a spoof drop BELOW the accepts is flagged as misplaced, pointing at it', () => {
  const rs = [
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -i lo -j ACCEPT',
    '-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT',
    '-A INPUT -s 127.0.0.0/8 -j DROP',
    'COMMIT',
  ].join('\n');
  const hits = FS.lint(FS.parse(rs)).findings.filter((f) => f.id === 'missing-loopback-spoof-drop');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].ruleIdx, 2);
  assert.match(hits[0].title, /only after/);
});

test('without the lo accept the chain is loopback-not-allowed territory, not this smell', () => {
  const rs = [
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT',
    'COMMIT',
  ].join('\n');
  const ids = new Set(FS.lint(FS.parse(rs)).findings.map((f) => f.id));
  assert.ok(!ids.has('missing-loopback-spoof-drop'), 'the pair smell stays quiet');
  assert.ok(ids.has('loopback-not-allowed'), 'the broken-loopback smell speaks instead');
});

test('missing-loopback-spoof-drop reads the nft and IPv6 spellings', () => {
  const nft = [
    'table inet filter {',
    '	chain input {',
    '		type filter hook input priority 0; policy drop;',
    '		iifname "lo" accept',
    '		ip saddr 127.0.0.0/8 drop',
    '		tcp dport 80 accept',
    '	}',
    '}',
  ].join('\n');
  assert.ok(!FS.lint(FS.parse(nft)).findings.some((f) => f.id === 'missing-loopback-spoof-drop'));
  const v6 = [
    '# Generated by ip6tables-save',
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -i lo -j ACCEPT',
    '-A INPUT -s ::1/128 -j DROP',
    '-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT',
    'COMMIT',
  ].join('\n');
  assert.ok(!FS.lint(FS.parse(v6)).findings.some((f) => f.id === 'missing-loopback-spoof-drop'));
});

test('missing-loopback-spoof-drop is skipped for ufw', () => {
  assert.ok(!lintIds('ufw-status.txt').has('missing-loopback-spoof-drop'));
});

// --- ipv6-unfiltered (v1.17.0) ---------------------------------------------

test('ipv6-unfiltered fires on a locked family-ip table with no v6 coverage', () => {
  const found = lintIds('nft-v4only.txt');
  assert.ok(found.has('ipv6-unfiltered'));
});

test('ipv6-unfiltered stays quiet when an inet table hooks input', () => {
  assert.ok(!lintIds('nft-ruleset.txt').has('ipv6-unfiltered'));
});

test('ipv6-unfiltered defers to missing-input-drop when a v6 input hook exists', () => {
  const nft = [
    'table ip filter {',
    '	chain input {',
    '		type filter hook input priority filter; policy drop;',
    '		iifname "lo" accept',
    '		tcp dport 80 accept',
    '	}',
    '}',
    'table ip6 filter {',
    '	chain input {',
    '		type filter hook input priority filter; policy accept;',
    '		tcp dport 80 accept',
    '	}',
    '}',
  ].join('\n');
  const { findings } = FS.lint(FS.parse(nft));
  assert.ok(!findings.some((f) => f.id === 'ipv6-unfiltered'));
  // The open v6 chain is missing-input-drop's job, and it does speak.
  assert.ok(findings.some((f) => f.id === 'missing-input-drop' && f.tableFamily === 'ip6'));
});

test('ipv6-unfiltered needs a deny-postured v4 input to fire at all', () => {
  const nft = [
    'table ip filter {',
    '	chain input {',
    '		type filter hook input priority filter; policy accept;',
    '		tcp dport 80 accept',
    '	}',
    '}',
  ].join('\n');
  assert.ok(!FS.lint(FS.parse(nft)).findings.some((f) => f.id === 'ipv6-unfiltered'));
});

test('ipv6-unfiltered never fires for iptables pastes (other family invisible)', () => {
  assert.ok(!lintIds('iptables-save.txt').has('ipv6-unfiltered'));
});

// --- dnat-forward-blocked (v1.18.0) ----------------------------------------

test('dnat-forward-blocked flags the DNAT whose FORWARD accept is missing', () => {
  const { findings } = FS.lint(FS.parse(sample('iptables-dnat-dead.txt')));
  const blocked = findings.filter((f) => f.id === 'dnat-forward-blocked');
  // Only the :15432 -> 10.0.0.30:5432 publish lacks a FORWARD accept.
  assert.equal(blocked.length, 1);
  assert.match(blocked[0].title, /10\.0\.0\.30:5432/);
});

test('dnat-forward-blocked stays quiet when every target has a FORWARD accept', () => {
  // The portforward sample cables all three forwarded DNAT targets in
  // FORWARD; the fourth DNAT rewrites to loopback, which is delivered
  // locally and never traverses FORWARD (dnat-to-loopback's business).
  assert.ok(!lintIds('iptables-portforward.txt').has('dnat-forward-blocked'));
});

test('dnat-forward-blocked does not fire when FORWARD is open (accept policy)', () => {
  const rs = [
    '*filter', ':INPUT DROP [0:0]', ':FORWARD ACCEPT [0:0]', ':OUTPUT ACCEPT [0:0]',
    '-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT',
    'COMMIT',
    '*nat', ':PREROUTING ACCEPT [0:0]', ':POSTROUTING ACCEPT [0:0]',
    '-A PREROUTING -i eth0 -p tcp --dport 2222 -j DNAT --to-destination 10.0.0.20:22',
    'COMMIT',
  ].join('\n');
  assert.ok(!FS.lint(FS.parse(rs)).findings.some((f) => f.id === 'dnat-forward-blocked'));
});

test('dnat-forward-blocked: an established-only FORWARD accept does NOT count as coverage', () => {
  // Deny FORWARD with only a conntrack ESTABLISHED,RELATED rule — the NEW
  // forwarded packet has nothing to match, so the forward is dead.
  const rs = [
    '*filter', ':INPUT DROP [0:0]', ':FORWARD DROP [0:0]', ':OUTPUT ACCEPT [0:0]',
    '-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT',
    '-A FORWARD -j DROP',
    'COMMIT',
    '*nat', ':PREROUTING ACCEPT [0:0]', ':POSTROUTING ACCEPT [0:0]',
    '-A PREROUTING -i eth0 -p tcp --dport 8080 -j DNAT --to-destination 10.0.0.50:80',
    'COMMIT',
  ].join('\n');
  const blocked = FS.lint(FS.parse(rs)).findings.filter((f) => f.id === 'dnat-forward-blocked');
  assert.equal(blocked.length, 1);
  assert.match(blocked[0].title, /10\.0\.0\.50:80/);
});

test('dnat-forward-blocked: a subnet FORWARD accept covers a host target', () => {
  // FORWARD accepts the whole 10.0.0.0/24 on port 80 → the /32 target is covered.
  const rs = [
    '*filter', ':INPUT DROP [0:0]', ':FORWARD DROP [0:0]', ':OUTPUT ACCEPT [0:0]',
    '-A FORWARD -d 10.0.0.0/24 -p tcp --dport 80 -j ACCEPT',
    '-A FORWARD -j DROP',
    'COMMIT',
    '*nat', ':PREROUTING ACCEPT [0:0]', ':POSTROUTING ACCEPT [0:0]',
    '-A PREROUTING -i eth0 -p tcp --dport 8080 -j DNAT --to-destination 10.0.0.50:80',
    'COMMIT',
  ].join('\n');
  assert.ok(!FS.lint(FS.parse(rs)).findings.some((f) => f.id === 'dnat-forward-blocked'));
});

test('dnat-forward-blocked fires for nftables too', () => {
  const nft = [
    'table ip filter {',
    '\tchain forward {',
    '\t\ttype filter hook forward priority filter; policy drop;',
    '\t\tct state established,related accept',
    '\t}',
    '}',
    'table ip nat {',
    '\tchain prerouting {',
    '\t\ttype nat hook prerouting priority dstnat; policy accept;',
    '\t\tiifname "eth0" tcp dport 8443 dnat to 10.0.0.60:443',
    '\t}',
    '}',
  ].join('\n');
  const blocked = FS.lint(FS.parse(nft)).findings.filter((f) => f.id === 'dnat-forward-blocked');
  assert.equal(blocked.length, 1);
  assert.match(blocked[0].title, /10\.0\.0\.60:443/);
});

// --- bogon-source-accept (v1.19.0) -----------------------------------------

test('bogon-source-accept flags an ACCEPT trusting a non-routable source', () => {
  const rs = [
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -s 169.254.0.0/16 -j ACCEPT',
    '-A INPUT -s 192.0.2.10/32 -p tcp --dport 80 -j ACCEPT',
    'COMMIT',
  ].join('\n');
  const found = FS.lint(FS.parse(rs)).findings.filter((f) => f.id === 'bogon-source-accept');
  assert.equal(found.length, 2);
  assert.match(found[0].title, /169\.254\.0\.0\/16/);
});

test('bogon-source-accept spares public, private and CGNAT sources', () => {
  const rs = [
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -s 8.8.8.8/32 -j ACCEPT',      // public — fine
    '-A INPUT -s 10.0.0.0/8 -j ACCEPT',      // RFC1918 — legitimate LAN
    '-A INPUT -s 100.64.0.0/10 -j ACCEPT',   // CGNAT — legitimate behind some ISPs
    '-A INPUT -s 192.168.1.0/24 -j ACCEPT',
    'COMMIT',
  ].join('\n');
  assert.ok(!FS.lint(FS.parse(rs)).findings.some((f) => f.id === 'bogon-source-accept'));
});

test('bogon-source-accept does NOT flag DROP/REJECT of a bogon (that is correct anti-spoofing)', () => {
  const rs = [
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -s 240.0.0.0/4 -j DROP',
    '-A INPUT -s 0.0.0.0/8 -j DROP',
    'COMMIT',
  ].join('\n');
  assert.ok(!FS.lint(FS.parse(rs)).findings.some((f) => f.id === 'bogon-source-accept'));
});

test('bogon-source-accept leaves loopback to its own smells', () => {
  // 127/8 as a source is loopback-not-allowed / missing-loopback-spoof-drop
  // territory, not this smell's — so a 127/8 ACCEPT does not trip bogon.
  const rs = [
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -s 127.0.0.0/8 -j ACCEPT',
    'COMMIT',
  ].join('\n');
  assert.ok(!FS.lint(FS.parse(rs)).findings.some((f) => f.id === 'bogon-source-accept'));
});

test('bogon-source-accept catches the v6 documentation prefix too', () => {
  const rs = [
    '# Generated by ip6tables-save',
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -s 2001:db8::/32 -j ACCEPT',
    'COMMIT',
  ].join('\n');
  assert.ok(FS.lint(FS.parse(rs)).findings.some((f) => f.id === 'bogon-source-accept'));
});

// --- log-without-prefix (v1.20.0) ------------------------------------------

test('log-without-prefix flags an unlabelled LOG rule', () => {
  const rs = [
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -j LOG',
    '-A INPUT -j DROP',
    'COMMIT',
  ].join('\n');
  const found = FS.lint(FS.parse(rs)).findings.filter((f) => f.id === 'log-without-prefix');
  assert.equal(found.length, 1);
});

test('log-without-prefix stays quiet when the LOG carries a prefix', () => {
  const rs = [
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -j LOG --log-prefix "DROP-INPUT: "',
    '-A INPUT -j DROP',
    'COMMIT',
  ].join('\n');
  assert.ok(!FS.lint(FS.parse(rs)).findings.some((f) => f.id === 'log-without-prefix'));
});

test('log-without-prefix understands nft `log prefix` and NFLOG --nflog-prefix', () => {
  const nftPrefixed = [
    'table inet filter {',
    '\tchain input {',
    '\t\ttype filter hook input priority filter; policy drop;',
    '\t\tlog prefix "DROP: " drop',
    '\t}',
    '}',
  ].join('\n');
  assert.ok(!FS.lint(FS.parse(nftPrefixed)).findings.some((f) => f.id === 'log-without-prefix'));

  const nftBare = [
    'table inet filter {',
    '\tchain input {',
    '\t\ttype filter hook input priority filter; policy drop;',
    '\t\tlog drop',
    '\t}',
    '}',
  ].join('\n');
  assert.ok(FS.lint(FS.parse(nftBare)).findings.some((f) => f.id === 'log-without-prefix'));

  const nflog = ['*filter', ':INPUT DROP [0:0]', '-A INPUT -j NFLOG --nflog-prefix "x"', 'COMMIT'].join('\n');
  assert.ok(!FS.lint(FS.parse(nflog)).findings.some((f) => f.id === 'log-without-prefix'));
});

test('log-without-prefix is skipped for ufw', () => {
  assert.ok(!lintIds('ufw-status.txt').has('log-without-prefix'));
});

// --- dnat-unscoped (v1.21.0) ------------------------------------------------

test('dnat-unscoped fires on a DNAT with neither -d nor -i', () => {
  const rs = [
    '*nat', ':PREROUTING ACCEPT [0:0]',
    '-A PREROUTING -p tcp --dport 8080 -j DNAT --to-destination 10.0.0.5:8080',
    'COMMIT',
  ].join('\n');
  const found = FS.lint(FS.parse(rs)).findings.filter((f) => f.id === 'dnat-unscoped');
  assert.equal(found.length, 1);
});

test('dnat-unscoped stays quiet when the DNAT is scoped by -d or by -i', () => {
  const byAddr = [
    '*nat', ':PREROUTING ACCEPT [0:0]',
    '-A PREROUTING -d 203.0.113.7/32 -p tcp --dport 8080 -j DNAT --to-destination 10.0.0.5:8080',
    'COMMIT',
  ].join('\n');
  assert.ok(!FS.lint(FS.parse(byAddr)).findings.some((f) => f.id === 'dnat-unscoped'));

  const byIface = [
    '*nat', ':PREROUTING ACCEPT [0:0]',
    '-A PREROUTING -i eth0 -p tcp --dport 8080 -j DNAT --to-destination 10.0.0.5:8080',
    'COMMIT',
  ].join('\n');
  assert.ok(!FS.lint(FS.parse(byIface)).findings.some((f) => f.id === 'dnat-unscoped'));
});

test('dnat-unscoped exempts REDIRECT (transparent proxies match any destination)', () => {
  const rs = [
    '*nat', ':PREROUTING ACCEPT [0:0]',
    '-A PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports 3128',
    'COMMIT',
  ].join('\n');
  assert.ok(!FS.lint(FS.parse(rs)).findings.some((f) => f.id === 'dnat-unscoped'));
});

test('dnat-unscoped understands nft: bare `dnat to` fires, iifname/daddr scoping does not', () => {
  const bare = [
    'table ip nat {',
    '\tchain prerouting {',
    '\t\ttype nat hook prerouting priority dstnat;',
    '\t\ttcp dport 8080 dnat to 10.0.0.5:8080',
    '\t}',
    '}',
  ].join('\n');
  assert.ok(FS.lint(FS.parse(bare)).findings.some((f) => f.id === 'dnat-unscoped'));

  const scoped = [
    'table ip nat {',
    '\tchain prerouting {',
    '\t\ttype nat hook prerouting priority dstnat;',
    '\t\tiifname "eth0" tcp dport 8080 dnat to 10.0.0.5:8080',
    '\t\tip daddr 203.0.113.7 tcp dport 8443 dnat to 10.0.0.5:8443',
    '\t}',
    '}',
  ].join('\n');
  assert.ok(!FS.lint(FS.parse(scoped)).findings.some((f) => f.id === 'dnat-unscoped'));
});

test('dnat-unscoped does not fire on the portforward sample (all DNATs are -i scoped)', () => {
  assert.ok(!lintIds('iptables-portforward.txt').has('dnat-unscoped'));
});

// --- dnat-no-hairpin (v1.22.0) -----------------------------------------------

test('dnat-no-hairpin fires (info) when the only masquerade is out-interface-scoped', () => {
  const rs = [
    '*nat', ':PREROUTING ACCEPT [0:0]', ':POSTROUTING ACCEPT [0:0]',
    '-A PREROUTING -d 203.0.113.7/32 -p tcp --dport 8080 -j DNAT --to-destination 192.168.1.50:8080',
    '-A POSTROUTING -s 192.168.1.0/24 -o eth0 -j MASQUERADE',
    'COMMIT',
  ].join('\n');
  const found = FS.lint(FS.parse(rs)).findings.filter((f) => f.id === 'dnat-no-hairpin');
  assert.equal(found.length, 1);
  assert.equal(found[0].severity, 'info');
  assert.match(found[0].title, /192\.168\.1\.50:8080/);
});

test('dnat-no-hairpin is suppressed by the hairpin leg (destination-scoped masquerade)', () => {
  const rs = [
    '*nat', ':PREROUTING ACCEPT [0:0]', ':POSTROUTING ACCEPT [0:0]',
    '-A PREROUTING -d 203.0.113.7/32 -p tcp --dport 8080 -j DNAT --to-destination 192.168.1.50:8080',
    '-A POSTROUTING -s 192.168.1.0/24 -o eth0 -j MASQUERADE',
    '-A POSTROUTING -s 192.168.1.0/24 -d 192.168.1.50/32 -p tcp --dport 8080 -j MASQUERADE',
    'COMMIT',
  ].join('\n');
  assert.ok(!FS.lint(FS.parse(rs)).findings.some((f) => f.id === 'dnat-no-hairpin'));
});

test('dnat-no-hairpin is suppressed by a masquerade with no out-interface (covers the flow incidentally)', () => {
  const rs = [
    '*nat', ':PREROUTING ACCEPT [0:0]', ':POSTROUTING ACCEPT [0:0]',
    '-A PREROUTING -d 203.0.113.7/32 -p tcp --dport 8080 -j DNAT --to-destination 192.168.1.50:8080',
    '-A POSTROUTING -s 192.168.1.0/24 -j MASQUERADE',
    'COMMIT',
  ].join('\n');
  assert.ok(!FS.lint(FS.parse(rs)).findings.some((f) => f.id === 'dnat-no-hairpin'));
});

test('dnat-no-hairpin skips -i-scoped DNATs (LAN packets never match) and public targets', () => {
  const ifaceScoped = [
    '*nat', ':PREROUTING ACCEPT [0:0]', ':POSTROUTING ACCEPT [0:0]',
    '-A PREROUTING -i eth0 -p tcp --dport 8080 -j DNAT --to-destination 192.168.1.50:8080',
    '-A POSTROUTING -s 192.168.1.0/24 -o eth0 -j MASQUERADE',
    'COMMIT',
  ].join('\n');
  assert.ok(!FS.lint(FS.parse(ifaceScoped)).findings.some((f) => f.id === 'dnat-no-hairpin'));

  const publicTarget = [
    '*nat', ':PREROUTING ACCEPT [0:0]', ':POSTROUTING ACCEPT [0:0]',
    '-A PREROUTING -d 203.0.113.7/32 -p tcp --dport 8080 -j DNAT --to-destination 198.51.100.9:8080',
    '-A POSTROUTING -s 192.168.1.0/24 -o eth0 -j MASQUERADE',
    'COMMIT',
  ].join('\n');
  assert.ok(!FS.lint(FS.parse(publicTarget)).findings.some((f) => f.id === 'dnat-no-hairpin'));
});

test('dnat-no-hairpin stays quiet when POSTROUTING never NATs (not provably a router)', () => {
  const rs = [
    '*nat', ':PREROUTING ACCEPT [0:0]', ':POSTROUTING ACCEPT [0:0]',
    '-A PREROUTING -d 203.0.113.7/32 -p tcp --dport 8080 -j DNAT --to-destination 192.168.1.50:8080',
    'COMMIT',
  ].join('\n');
  assert.ok(!FS.lint(FS.parse(rs)).findings.some((f) => f.id === 'dnat-no-hairpin'));
});

test('dnat-no-hairpin understands nft: oifname-only masquerade fires, ip daddr hairpin leg does not', () => {
  const broken = [
    'table ip nat {',
    '\tchain prerouting {',
    '\t\ttype nat hook prerouting priority dstnat;',
    '\t\tip daddr 203.0.113.7 tcp dport 8080 dnat to 192.168.1.50:8080',
    '\t}',
    '\tchain postrouting {',
    '\t\ttype nat hook postrouting priority srcnat;',
    '\t\tip saddr 192.168.1.0/24 oifname "eth0" masquerade',
    '\t}',
    '}',
  ].join('\n');
  assert.ok(FS.lint(FS.parse(broken)).findings.some((f) => f.id === 'dnat-no-hairpin'));

  const fixed = [
    'table ip nat {',
    '\tchain prerouting {',
    '\t\ttype nat hook prerouting priority dstnat;',
    '\t\tip daddr 203.0.113.7 tcp dport 8080 dnat to 192.168.1.50:8080',
    '\t}',
    '\tchain postrouting {',
    '\t\ttype nat hook postrouting priority srcnat;',
    '\t\tip saddr 192.168.1.0/24 oifname "eth0" masquerade',
    '\t\tip saddr 192.168.1.0/24 ip daddr 192.168.1.50 masquerade',
    '\t}',
    '}',
  ].join('\n');
  assert.ok(!FS.lint(FS.parse(fixed)).findings.some((f) => f.id === 'dnat-no-hairpin'));
});

test('dnat-no-hairpin composes with dnat-unscoped on the sloppy router\'s hurried 8080 forward', () => {
  const { findings } = FS.lint(FS.parse(sample('iptables-router-sloppy.txt')));
  const hairpin = findings.filter((f) => f.id === 'dnat-no-hairpin');
  const unscoped = findings.filter((f) => f.id === 'dnat-unscoped');
  assert.equal(hairpin.length, 1);
  assert.equal(unscoped.length, 1);
  // Same rule, two different complaints: what else the rewrite swallows
  // (unscoped) and that LAN clients can't use the public address (hairpin).
  assert.equal(hairpin[0].ruleIdx, unscoped[0].ruleIdx);
  assert.equal(hairpin[0].chain, unscoped[0].chain);
});

test('dnat-no-hairpin does not fire on the portforward or dnat-dead samples (-i-scoped DNATs)', () => {
  assert.ok(!lintIds('iptables-portforward.txt').has('dnat-no-hairpin'));
  assert.ok(!lintIds('iptables-dnat-dead.txt').has('dnat-no-hairpin'));
});

// --- udp-amplifier-exposed ------------------------------------------------

test('udp-amplifier-exposed flags open UDP reflectors and names the multiplier', () => {
  const rs = [
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -p udp -m udp --dport 123 -j ACCEPT',
    '-A INPUT -p udp -m udp --dport 11211 -j ACCEPT',
    'COMMIT',
  ].join('\n');
  const hits = FS.lint(FS.parse(rs)).findings.filter((f) => f.id === 'udp-amplifier-exposed');
  assert.equal(hits.length, 2);
  assert.equal(hits[0].severity, 'warning');
  assert.match(hits[0].title, /ntp \(port 123, 556x amplification\)/);
  assert.match(hits[1].title, /memcached .*51,000x/);
});

test('udp-amplifier-exposed spares a restricted source, a rate limit and an ESTABLISHED gate', () => {
  const rs = [
    '*filter', ':INPUT DROP [0:0]',
    // A resolver for your own subnet is the normal, correct setup.
    '-A INPUT -p udp -m udp --dport 53 -s 192.168.1.0/24 -j ACCEPT',
    // A TOTAL ceiling is the right control for amplification: it caps what
    // this host can emit. Unlike the TCP brute-force case, global is fine.
    '-A INPUT -p udp -m udp --dport 123 -m limit --limit 10/sec -j ACCEPT',
    // Replies to the host's own queries, not a service anyone can reach.
    '-A INPUT -p udp -m udp --dport 1900 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT',
    // Blocking a reflector port is the fix, never the smell.
    '-A INPUT -p udp -m udp --dport 19 -j DROP',
    'COMMIT',
  ].join('\n');
  const ids = FS.lint(FS.parse(rs)).findings.map((f) => f.id);
  assert.ok(!ids.includes('udp-amplifier-exposed'));
});

test('udp-amplifier-exposed is UDP-only: the same port over TCP never reflects', () => {
  const rs = [
    '*filter', ':INPUT DROP [0:0]',
    // TCP needs a handshake, so the source address cannot be forged —
    // no reflection, whatever the port.
    '-A INPUT -p tcp -m tcp --dport 53 -j ACCEPT',
    'COMMIT',
  ].join('\n');
  const ids = FS.lint(FS.parse(rs)).findings.map((f) => f.id);
  assert.ok(!ids.includes('udp-amplifier-exposed'));
});

test('udp-amplifier-exposed judges only the inbound side: OUTPUT is the host\'s own client socket', () => {
  const rs = [
    '*filter', ':INPUT DROP [0:0]', ':OUTPUT ACCEPT [0:0]', ':SERVICES - [0:0]',
    // The host querying someone else's NTP server: legitimate egress.
    '-A OUTPUT -p udp -m udp --dport 123 -j ACCEPT',
    // Same match reached from INPUT through a user chain: that is a reflector.
    '-A INPUT -j SERVICES',
    '-A SERVICES -p udp -m udp --dport 123 -j ACCEPT',
    'COMMIT',
  ].join('\n');
  const hits = FS.lint(FS.parse(rs)).findings.filter((f) => f.id === 'udp-amplifier-exposed');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].chain, 'SERVICES');
});

test('udp-amplifier-exposed reads the nft spelling and nft sets', () => {
  const rs = [
    'table inet filter {',
    '	chain input {',
    '		type filter hook input priority 0; policy drop;',
    '		udp dport { 53, 123 } accept',
    '	}',
    '}',
  ].join('\n');
  const hits = FS.lint(FS.parse(rs)).findings.filter((f) => f.id === 'udp-amplifier-exposed');
  // One finding per rule, reported on the first amplifier port it matches.
  assert.equal(hits.length, 1);
  assert.equal(hits[0].chain, 'input');
  assert.match(hits[0].title, /dns/);
});

test('udp-amplifier-exposed treats a protocol-less ufw allow as UDP too (ufw allow 53 opens both)', () => {
  const rs = UFW_HEADER.concat([
    'Default: deny (incoming), allow (outgoing), disabled (routed)',
    '',
    'To                         Action      From',
    '--                         ------      ----',
    // Explicit /udp, and the bare spelling that opens BOTH transports.
    '1900/udp                   ALLOW IN    Anywhere',
    '53                         ALLOW IN    Anywhere',
    // Explicit /tcp cannot reflect, and a LAN-scoped one is legitimate.
    '11211/tcp                  ALLOW IN    Anywhere',
    '123/udp                    ALLOW IN    192.168.1.0/24',
  ]).join('\n');
  const hits = FS.lint(FS.parse(rs)).findings.filter((f) => f.id === 'udp-amplifier-exposed');
  assert.equal(hits.length, 2);
  assert.match(hits[0].title, /ssdp/);
  assert.match(hits[1].title, /dns/);
});

test('udp-amplifier-exposed composes with exposed-admin-port on open memcached UDP', () => {
  const rs = [
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -p udp -m udp --dport 11211 -j ACCEPT',
    'COMMIT',
  ].join('\n');
  const ids = FS.lint(FS.parse(rs)).findings.map((f) => f.id);
  // Two different costs on one rule: someone reading your cache
  // (exposed-admin-port) and your host attacking a stranger (this smell).
  assert.ok(ids.includes('exposed-admin-port'));
  assert.ok(ids.includes('udp-amplifier-exposed'));
});

test('the reflector sample fires on the widened resolver, memcached and SSDP — but not the capped NTP', () => {
  const hits = FS.lint(FS.parse(sample('iptables-reflector.txt')))
    .findings.filter((f) => f.id === 'udp-amplifier-exposed');
  assert.equal(hits.length, 3);
  const services = hits.map((f) => f.title.match(/reflector: (\S+)/)[1]);
  // JSON, not deepEqual: findings come from the linter's own realm, where
  // deepEqual sees "same structure, not reference-equal" (the recurring
  // cross-realm gotcha in this suite).
  assert.equal(JSON.stringify(services), JSON.stringify(['dns', 'memcached', 'ssdp']));
  // The LAN-scoped copy of the same port 53 rule sits right above the
  // flagged one: the finding must point at the source-less rule.
  assert.ok(hits[0].ruleIdx > 0);
});

// --- dnat-to-loopback (v1.31.0) ---------------------------------------------

test('dnat-to-loopback flags the PREROUTING DNAT to 127.0.0.1, names the target and the trap', () => {
  const rs = [
    '*nat', ':PREROUTING ACCEPT [0:0]', ':POSTROUTING ACCEPT [0:0]',
    '-A PREROUTING -i eth0 -p tcp --dport 8081 -j DNAT --to-destination 127.0.0.1:8081',
    'COMMIT',
  ].join('\n');
  const hits = FS.lint(FS.parse(rs)).findings.filter((f) => f.id === 'dnat-to-loopback');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].severity, 'warning');
  assert.match(hits[0].title, /127\.0\.0\.1:8081/);
  // Both halves of the argument travel in the details: dark by default,
  // and the forum fix is the CVE.
  assert.match(hits[0].details, /route_localnet/);
  assert.match(hits[0].details, /CVE-2020-8558/);
  assert.match(hits[0].details, /REDIRECT --to-ports 8081/);
});

test('dnat-to-loopback covers all of 127/8, not just 127.0.0.1 (127.0.0.53 is systemd-resolved)', () => {
  const rs = [
    '*nat', ':PREROUTING ACCEPT [0:0]', ':POSTROUTING ACCEPT [0:0]',
    '-A PREROUTING -i eth0 -p udp --dport 53 -j DNAT --to-destination 127.0.0.53:53',
    'COMMIT',
  ].join('\n');
  const findings = FS.lint(FS.parse(rs)).findings;
  assert.ok(findings.some((f) => f.id === 'dnat-to-loopback'));
  // ...and the sibling smell agrees the packet never traverses FORWARD:
  // a loopback rewrite with no FORWARD accept is NOT a blocked forward.
  assert.ok(!findings.some((f) => f.id === 'dnat-forward-blocked'));
});

test('dnat-to-loopback reads the v6 loopback from ip6tables and from nft', () => {
  const v6 = [
    '*nat', ':PREROUTING ACCEPT [0:0]',
    '-A PREROUTING -i eth0 -p tcp --dport 8080 -j DNAT --to-destination [::1]:8080',
    'COMMIT',
  ].join('\n');
  const v6hits = FS.lint(FS.parse(v6, 'ip6tables-save')).findings.filter((f) => f.id === 'dnat-to-loopback');
  assert.equal(v6hits.length, 1);
  assert.match(v6hits[0].title, /::1/);

  const nft = [
    'table ip6 nat {',
    '\tchain prerouting {',
    '\t\ttype nat hook prerouting priority dstnat;',
    '\t\ttcp dport 8080 dnat to [::1]:8080',
    '\t}',
    '}',
  ].join('\n');
  assert.ok(FS.lint(FS.parse(nft)).findings.some((f) => f.id === 'dnat-to-loopback'));
});

test('dnat-to-loopback understands the nft v4 form', () => {
  const nft = [
    'table ip nat {',
    '\tchain prerouting {',
    '\t\ttype nat hook prerouting priority dstnat;',
    '\t\tiifname "eth0" tcp dport 8081 dnat to 127.0.0.1:8081',
    '\t}',
    '}',
  ].join('\n');
  const hits = FS.lint(FS.parse(nft)).findings.filter((f) => f.id === 'dnat-to-loopback');
  assert.equal(hits.length, 1);
});

test('dnat-to-loopback spares REDIRECT: same "127.0.0.1" in the trace model, no loopback routing involved', () => {
  const rs = [
    '*nat', ':PREROUTING ACCEPT [0:0]', ':POSTROUTING ACCEPT [0:0]',
    '-A PREROUTING -i eth0 -p tcp --dport 8081 -j REDIRECT --to-ports 8081',
    'COMMIT',
  ].join('\n');
  assert.ok(!FS.lint(FS.parse(rs)).findings.some((f) => f.id === 'dnat-to-loopback'));
});

test('dnat-to-loopback spares -i lo DNATs and nat/OUTPUT rewrites (transparent local proxies)', () => {
  const onLoopback = [
    '*nat', ':PREROUTING ACCEPT [0:0]', ':POSTROUTING ACCEPT [0:0]',
    '-A PREROUTING -i lo -p tcp --dport 53 -j DNAT --to-destination 127.0.0.1:5353',
    'COMMIT',
  ].join('\n');
  assert.ok(!FS.lint(FS.parse(onLoopback)).findings.some((f) => f.id === 'dnat-to-loopback'));

  const natOutput = [
    '*nat', ':PREROUTING ACCEPT [0:0]', ':OUTPUT ACCEPT [0:0]',
    '-A OUTPUT -p tcp --dport 80 -j DNAT --to-destination 127.0.0.1:8080',
    'COMMIT',
  ].join('\n');
  assert.ok(!FS.lint(FS.parse(natOutput)).findings.some((f) => f.id === 'dnat-to-loopback'));
});

test('dnat-to-loopback stays quiet on ordinary forwards', () => {
  const rs = [
    '*nat', ':PREROUTING ACCEPT [0:0]', ':POSTROUTING ACCEPT [0:0]',
    '-A PREROUTING -i eth0 -p tcp --dport 8080 -j DNAT --to-destination 192.168.1.50:8080',
    'COMMIT',
  ].join('\n');
  assert.ok(!FS.lint(FS.parse(rs)).findings.some((f) => f.id === 'dnat-to-loopback'));
});

// --- docker-user-unfiltered --------------------------------------------------

// The minimal honest Docker wiring: filter FORWARD jumps DOCKER-USER (factory
// content: one RETURN), nat DOCKER holds the published port's DNAT.
function dockerRuleset({ dockerUserRules = ['-A DOCKER-USER -j RETURN'], natDockerRules = ['-A DOCKER ! -i docker0 -p tcp --dport 8080 -j DNAT --to-destination 172.17.0.2:80'], forwardJump = '-A FORWARD -j DOCKER-USER' } = {}) {
  return [
    '# Generated by iptables-save',
    '*filter',
    ':INPUT DROP [0:0]', ':FORWARD DROP [0:0]', ':OUTPUT ACCEPT [0:0]',
    ':DOCKER - [0:0]', ':DOCKER-USER - [0:0]',
    '-A INPUT -i lo -j ACCEPT',
    '-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT',
    ...(forwardJump ? [forwardJump] : []),
    '-A FORWARD -o docker0 -j DOCKER',
    '-A DOCKER -d 172.17.0.2/32 ! -i docker0 -o docker0 -p tcp --dport 80 -j ACCEPT',
    ...dockerUserRules,
    'COMMIT',
    '*nat',
    ':PREROUTING ACCEPT [0:0]', ':POSTROUTING ACCEPT [0:0]', ':DOCKER - [0:0]',
    '-A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER',
    '-A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE',
    '-A DOCKER -i docker0 -j RETURN',
    ...natDockerRules,
    'COMMIT',
  ].join('\n');
}

test('docker-user-unfiltered fires once on a factory DOCKER-USER with a published port', () => {
  const findings = FS.lint(FS.parse(dockerRuleset())).findings
    .filter((f) => f.id === 'docker-user-unfiltered');
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, 'warning');
  assert.equal(findings[0].chain, 'DOCKER-USER');
  assert.match(findings[0].title, /8080/);
  // the fix must name the mechanism, not just the symptom
  assert.match(findings[0].details, /never traverses INPUT/);
  assert.match(findings[0].details, /ctorigdstport/);
});

test('docker-user-unfiltered: the DNAT family is blind here — that is the point', () => {
  // Docker's DNAT lives in the user chain DOCKER, not in nat/PREROUTING
  // itself, so none of the PREROUTING-dispatched DNAT smells can speak.
  const ids = new Set(FS.lint(FS.parse(dockerRuleset())).findings.map((f) => f.id));
  assert.ok(!ids.has('exposed-via-dnat'));
  assert.ok(!ids.has('dnat-unscoped'));
  assert.ok(!ids.has('dnat-forward-blocked'));
  assert.ok(ids.has('docker-user-unfiltered'));
});

test('docker-user-unfiltered stays quiet when the operator wrote a real rule', () => {
  const rs = dockerRuleset({
    dockerUserRules: [
      '-A DOCKER-USER -i eth0 ! -s 10.0.0.0/8 -j DROP',
      '-A DOCKER-USER -j RETURN',
    ],
  });
  const ids = new Set(FS.lint(FS.parse(rs)).findings.map((f) => f.id));
  assert.ok(!ids.has('docker-user-unfiltered'), 'one real rule means the operator knows the mechanism');
});

test('docker-user-unfiltered stays quiet with no published port (no DNAT in DOCKER)', () => {
  const rs = dockerRuleset({ natDockerRules: [] });
  const ids = new Set(FS.lint(FS.parse(rs)).findings.map((f) => f.id));
  assert.ok(!ids.has('docker-user-unfiltered'), 'nothing published, the factory chain is just the default');
});

test('docker-user-unfiltered stays quiet when FORWARD never jumps to DOCKER-USER', () => {
  const rs = dockerRuleset({ forwardJump: null });
  const ids = new Set(FS.lint(FS.parse(rs)).findings.map((f) => f.id));
  assert.ok(!ids.has('docker-user-unfiltered'), 'unwired chain: nothing consults it (unused-chain territory)');
});

test('docker-user-unfiltered fires on a completely empty DOCKER-USER too', () => {
  // A flushed DOCKER-USER has zero rules and still filters nothing.
  const rs = dockerRuleset({ dockerUserRules: [] });
  const ids = new Set(FS.lint(FS.parse(rs)).findings.map((f) => f.id));
  assert.ok(ids.has('docker-user-unfiltered'));
});

test('docker-user-unfiltered reads the nftables spelling of the same wiring', () => {
  const rs = [
    'table ip filter {',
    '  chain INPUT {',
    '    type filter hook input priority filter; policy drop;',
    '    iifname "lo" accept',
    '  }',
    '  chain FORWARD {',
    '    type filter hook forward priority filter; policy drop;',
    '    counter jump DOCKER-USER',
    '    oifname "docker0" counter jump DOCKER',
    '  }',
    '  chain DOCKER {',
    '    ip daddr 172.17.0.2 oifname "docker0" tcp dport 80 counter accept',
    '  }',
    '  chain DOCKER-USER {',
    '    counter return',
    '  }',
    '}',
    'table ip nat {',
    '  chain PREROUTING {',
    '    type nat hook prerouting priority dstnat; policy accept;',
    '    fib daddr type local counter jump DOCKER',
    '  }',
    '  chain DOCKER {',
    '    iifname != "docker0" tcp dport 8080 counter dnat to 172.17.0.2:80',
    '  }',
    '}',
  ].join('\n');
  const findings = FS.lint(FS.parse(rs)).findings
    .filter((f) => f.id === 'docker-user-unfiltered');
  assert.equal(findings.length, 1);
  assert.match(findings[0].title, /8080/);
});

test('the docker sample stars the new smell and keeps the noise pinned down', () => {
  const found = lintIds('iptables-docker-open.txt');
  assert.ok(found.has('docker-user-unfiltered'));
  // the carefully-hardened INPUT must NOT produce findings of its own
  for (const quiet of [
    'missing-input-drop', 'missing-established-accept', 'missing-loopback-spoof-drop',
    'drop-without-log', 'unlimited-log', 'log-without-prefix', 'unlimited-icmp-echo',
    'admin-port-no-rate-limit', 'rate-limit-not-per-source', 'shadowed-rule',
    'duplicate-rule', 'unused-chain', 'masquerade-any-source',
  ]) {
    // admin-port-no-rate-limit CAN fire on the DOCKER accept (5432, no
    // throttle) — assert only that no finding lands on the INPUT chain.
    const hits = FS.lint(FS.parse(sample('iptables-docker-open.txt'))).findings
      .filter((f) => f.id === quiet && f.chain === 'INPUT');
    assert.equal(hits.length, 0, `'${quiet}' should not fire on the hardened INPUT`);
  }
});

// --- notrack-defeats-state-match -------------------------------------------

const NOTRACK_RAW = [
  '*raw', ':PREROUTING ACCEPT [0:0]', ':OUTPUT ACCEPT [0:0]',
  '-A PREROUTING -p udp --dport 53 -j CT --notrack',
  'COMMIT',
];

function notrackRs(inputRules, policy = 'DROP') {
  return NOTRACK_RAW.concat([
    '*filter', `:INPUT ${policy} [0:0]`, ':FORWARD DROP [0:0]', ':OUTPUT ACCEPT [0:0]',
  ], inputRules, ['COMMIT']).join('\n');
}

test('notrack-defeats-state-match fires when the only covering accept is state-qualified', () => {
  const rs = notrackRs([
    '-A INPUT -p udp --dport 53 -m conntrack --ctstate NEW -j ACCEPT',
  ]);
  const findings = FS.lint(FS.parse(rs)).findings.filter((f) => f.id === 'notrack-defeats-state-match');
  assert.equal(findings.length, 1);
  assert.equal(findings[0].chain, 'PREROUTING');
  assert.match(findings[0].title, /udp\/53/);
});

test('the legacy -j NOTRACK target fires too', () => {
  const rs = [
    '*raw', ':PREROUTING ACCEPT [0:0]',
    '-A PREROUTING -p udp --dport 123 -j NOTRACK',
    'COMMIT',
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT',
    '-A INPUT -p udp --dport 123 -m state --state NEW -j ACCEPT',
    'COMMIT',
  ].join('\n');
  const ids = new Set(FS.lint(FS.parse(rs)).findings.map((f) => f.id));
  assert.ok(ids.has('notrack-defeats-state-match'));
});

test('a stateless covering accept dissolves the trap', () => {
  const rs = notrackRs([
    '-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT',
    '-A INPUT -p udp --dport 53 -j ACCEPT',
  ]);
  const ids = new Set(FS.lint(FS.parse(rs)).findings.map((f) => f.id));
  assert.ok(!ids.has('notrack-defeats-state-match'));
});

test('an accept that matches UNTRACKED explicitly dissolves the trap', () => {
  const rs = notrackRs([
    '-A INPUT -p udp --dport 53 -m conntrack --ctstate UNTRACKED -j ACCEPT',
  ]);
  const ids = new Set(FS.lint(FS.parse(rs)).findings.map((f) => f.id));
  assert.ok(!ids.has('notrack-defeats-state-match'));
});

test('an open INPUT means the untracked packet gets in - no finding', () => {
  const rs = notrackRs([
    '-A INPUT -p udp --dport 53 -m conntrack --ctstate NEW -j ACCEPT',
  ], 'ACCEPT');
  const ids = new Set(FS.lint(FS.parse(rs)).findings.map((f) => f.id));
  assert.ok(!ids.has('notrack-defeats-state-match'));
});

test('no covering accept at all is not this smell\'s story', () => {
  const rs = notrackRs([
    '-A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT',
  ]);
  const ids = new Set(FS.lint(FS.parse(rs)).findings.map((f) => f.id));
  assert.ok(!ids.has('notrack-defeats-state-match'));
});

test('an accept for another port does not cover the notracked one', () => {
  const rs = notrackRs([
    '-A INPUT -p udp --dport 514 -m conntrack --ctstate NEW -j ACCEPT',
    '-A INPUT -p udp --dport 53 -j ACCEPT',
  ]);
  const ids = new Set(FS.lint(FS.parse(rs)).findings.map((f) => f.id));
  assert.ok(!ids.has('notrack-defeats-state-match'));
});

test('nft notrack in a prerouting hook fires against a ct state accept', () => {
  const rs = [
    'table ip raw {',
    '  chain prerouting {',
    '    type filter hook prerouting priority raw; policy accept;',
    '    udp dport 53 notrack',
    '  }',
    '}',
    'table ip filter {',
    '  chain input {',
    '    type filter hook input priority filter; policy drop;',
    '    ct state established,related accept',
    '    udp dport 53 ct state new accept',
    '  }',
    '}',
  ].join('\n');
  const findings = FS.lint(FS.parse(rs)).findings.filter((f) => f.id === 'notrack-defeats-state-match');
  assert.equal(findings.length, 1);
  assert.match(findings[0].title, /udp\/53/);
});

test('the notrack sample tells the DNS story: udp/53 dead, tcp/53 alive', () => {
  const findings = FS.lint(FS.parse(sample('iptables-notrack-dns.txt'))).findings
    .filter((f) => f.id === 'notrack-defeats-state-match');
  // one finding: the PREROUTING notrack (raw OUTPUT is the reply path, not inbound)
  assert.equal(findings.length, 1);
  assert.equal(findings[0].table, 'raw');
  assert.match(findings[0].title, /udp\/53/);
});

// --- conntrack-helper-enabled ----------------------------------------------

test('conntrack-helper-enabled fires on the CT target, the -m helper match, and nft ct helper set', () => {
  const ipt = [
    '*raw', ':PREROUTING ACCEPT [0:0]',
    '-A PREROUTING -p tcp --dport 21 -j CT --helper ftp',
    'COMMIT',
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -p tcp -m helper --helper sip -j ACCEPT',
    'COMMIT',
  ].join('\n');
  const f = FS.lint(FS.parse(ipt)).findings.filter((x) => x.id === 'conntrack-helper-enabled');
  assert.equal(f.length, 2);
  assert.ok(f.some((x) => /ftp/.test(x.title) && x.table === 'raw'));
  assert.ok(f.some((x) => /sip/.test(x.title) && x.chain === 'INPUT'));

  const nft = [
    'table ip filter {',
    '  chain input {',
    '    type filter hook input priority filter; policy drop;',
    '    tcp dport 21 ct helper set "ftp"',
    '  }',
    '}',
  ].join('\n');
  const g = FS.lint(FS.parse(nft)).findings.filter((x) => x.id === 'conntrack-helper-enabled');
  assert.equal(g.length, 1);
  assert.match(g[0].title, /ftp/);
});

test('conntrack-helper-enabled stays quiet on a ruleset with no helper', () => {
  const rs = [
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT',
    '-A INPUT -p tcp --dport 21 -j ACCEPT',
    'COMMIT',
  ].join('\n');
  const ids = new Set(FS.lint(FS.parse(rs)).findings.map((f) => f.id));
  assert.ok(!ids.has('conntrack-helper-enabled'));
});

test('the ftp-helper sample names the helper and stays otherwise clean of noise', () => {
  const findings = FS.lint(FS.parse(sample('iptables-ftp-helper.txt'))).findings
    .filter((f) => f.id === 'conntrack-helper-enabled');
  assert.equal(findings.length, 1);
  assert.match(findings[0].title, /ftp/);
  assert.equal(findings[0].table, 'raw');
});

// --- notrack-one-way ---------------------------------------------------------

test('notrack-one-way fires on an inbound-only NOTRACK and names the missing outbound half', () => {
  const rs = [
    '*raw', ':PREROUTING ACCEPT [0:0]', ':OUTPUT ACCEPT [0:0]',
    '-A PREROUTING -p udp --dport 123 -j CT --notrack',
    'COMMIT',
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -p udp --dport 123 -j ACCEPT',
    'COMMIT',
  ].join('\n');
  const f = FS.lint(FS.parse(rs)).findings.filter((x) => x.id === 'notrack-one-way');
  assert.equal(f.length, 1);
  assert.equal(f[0].chain, 'PREROUTING');
  assert.match(f[0].title, /udp\/123/);
  assert.match(f[0].details, /raw\/OUTPUT/);
  assert.match(f[0].details, /udp sport 123/);
});

test('notrack-one-way goes quiet when the outbound twin exists (the canonical pair)', () => {
  const rs = [
    '*raw', ':PREROUTING ACCEPT [0:0]', ':OUTPUT ACCEPT [0:0]',
    '-A PREROUTING -p udp --dport 123 -j CT --notrack',
    '-A OUTPUT -p udp --sport 123 -j CT --notrack',
    'COMMIT',
  ].join('\n');
  const ids = new Set(FS.lint(FS.parse(rs)).findings.map((x) => x.id));
  assert.ok(!ids.has('notrack-one-way'), 'the pair is complete');
});

test('notrack-one-way judges the outbound direction too (OUTPUT half without PREROUTING)', () => {
  const rs = [
    '*raw', ':PREROUTING ACCEPT [0:0]', ':OUTPUT ACCEPT [0:0]',
    '-A OUTPUT -p udp --sport 123 -j CT --notrack',
    'COMMIT',
  ].join('\n');
  const f = FS.lint(FS.parse(rs)).findings.filter((x) => x.id === 'notrack-one-way');
  assert.equal(f.length, 1);
  assert.equal(f[0].chain, 'OUTPUT');
  assert.match(f[0].details, /raw\/PREROUTING/);
  assert.match(f[0].details, /udp dport 123/);
});

test('notrack-one-way reads both nft spellings and respects the nft pair', () => {
  const oneWay = [
    'table ip raw {',
    '  chain prerouting {',
    '    type filter hook prerouting priority raw; policy accept;',
    '    udp dport 53 notrack',
    '  }',
    '}',
  ].join('\n');
  const f = FS.lint(FS.parse(oneWay)).findings.filter((x) => x.id === 'notrack-one-way');
  assert.equal(f.length, 1);
  assert.match(f[0].title, /udp\/53/);

  const pair = [
    'table ip raw {',
    '  chain prerouting {',
    '    type filter hook prerouting priority raw; policy accept;',
    '    udp dport 53 notrack',
    '  }',
    '  chain output {',
    '    type filter hook output priority raw; policy accept;',
    '    udp sport 53 notrack',
    '  }',
    '}',
  ].join('\n');
  const ids = new Set(FS.lint(FS.parse(pair)).findings.map((x) => x.id));
  assert.ok(!ids.has('notrack-one-way'), 'the nft pair is complete');
});

test('notrack-one-way stays conservative: a bare or port-less NOTRACK is not judged', () => {
  const rs = [
    '*raw', ':PREROUTING ACCEPT [0:0]',
    '-A PREROUTING -j NOTRACK',
    '-A PREROUTING -p udp -j CT --notrack',
    'COMMIT',
  ].join('\n');
  const ids = new Set(FS.lint(FS.parse(rs)).findings.map((x) => x.id));
  assert.ok(!ids.has('notrack-one-way'), 'nothing port-qualified to judge');
});

test('notrack-one-way accepts a proto-wide mirror as covering (broader than needed is fine)', () => {
  const rs = [
    '*raw', ':PREROUTING ACCEPT [0:0]', ':OUTPUT ACCEPT [0:0]',
    '-A PREROUTING -p udp --dport 53 -j CT --notrack',
    '-A OUTPUT -p udp -j CT --notrack',
    'COMMIT',
  ].join('\n');
  const ids = new Set(FS.lint(FS.parse(rs)).findings.map((x) => x.id));
  assert.ok(!ids.has('notrack-one-way'), 'the proto-wide OUTPUT notrack covers the replies');
});

test('the notrack-dns sample stays clean of notrack-one-way (its pair is complete) and the new sample fires exactly it', () => {
  const dns = new Set(FS.lint(FS.parse(sample('iptables-notrack-dns.txt'))).findings.map((x) => x.id));
  assert.ok(!dns.has('notrack-one-way'), 'the DNS sample models the full recipe');
  const f = FS.lint(FS.parse(sample('iptables-notrack-oneway.txt'))).findings;
  const mine = f.filter((x) => x.id === 'notrack-one-way');
  assert.equal(mine.length, 1);
  assert.match(mine[0].title, /udp\/123/);
  assert.ok(!f.some((x) => x.id === 'notrack-defeats-state-match'), 'the stateless accept serves the flow');
  assert.ok(!f.some((x) => x.id === 'udp-amplifier-exposed'), 'the rate limit exempts the NTP accept');
});

// --- unreachable-after-accept-all --------------------------------------------

test('unreachable-after-accept-all flags every rule below an unconditional ACCEPT', () => {
  const rs = [
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -i lo -j ACCEPT',
    '-A INPUT -j ACCEPT',
    '-A INPUT -p tcp --dport 22 -j ACCEPT',
    '-A INPUT -m conntrack --ctstate INVALID -j DROP',
    'COMMIT',
  ].join('\n');
  const f = FS.lint(FS.parse(rs)).findings.filter((x) => x.id === 'unreachable-after-accept-all');
  assert.equal(f.length, 2);
  assert.ok(f.every((x) => /catch-all ACCEPT at rule #2/.test(x.title)));
  assert.ok(f.some((x) => /--dport 22/.test(x.details)));
});

test('unreachable-after-accept-all stays quiet when the ACCEPT has any match', () => {
  const rs = [
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -i lo -j ACCEPT',
    '-A INPUT -p tcp --dport 443 -j ACCEPT',
    '-A INPUT -p tcp --dport 22 -j ACCEPT',
    'COMMIT',
  ].join('\n');
  const ids = new Set(FS.lint(FS.parse(rs)).findings.map((x) => x.id));
  assert.ok(!ids.has('unreachable-after-accept-all'), 'a scoped ACCEPT terminates only its own packets');
});

test('unreachable-after-accept-all: RETURN is not terminal, so it does not trigger', () => {
  const rs = [
    '*filter', ':INPUT DROP [0:0]',
    ':myset - [0:0]',
    '-A INPUT -j myset',
    '-A myset -j RETURN',
    '-A myset -p tcp --dport 22 -j ACCEPT',
    'COMMIT',
  ].join('\n');
  const ids = new Set(FS.lint(FS.parse(rs)).findings.map((x) => x.id));
  assert.ok(!ids.has('unreachable-after-accept-all'), 'RETURN leaves the chain, it does not accept-and-stop');
});

test('unreachable-after-accept-all reads the nft unconditional accept too', () => {
  const nft = [
    'table ip filter {',
    '  chain input {',
    '    type filter hook input priority filter; policy drop;',
    '    iifname "lo" accept',
    '    accept',
    '    tcp dport 22 accept',
    '  }',
    '}',
  ].join('\n');
  const f = FS.lint(FS.parse(nft)).findings.filter((x) => x.id === 'unreachable-after-accept-all');
  assert.equal(f.length, 1);
  assert.match(f[0].details, /tcp dport 22/);
});

test('the accept-all-dead sample flags the dead rules AND composes with permissive-accept', () => {
  const findings = FS.lint(FS.parse(sample('iptables-accept-all-dead.txt'))).findings;
  const dead = findings.filter((x) => x.id === 'unreachable-after-accept-all');
  // 5 rules sit below the catch-all ACCEPT (rule #3): the recent --set, the
  // recent --update drop, the ssh accept, the INVALID drop and the LOG.
  assert.equal(dead.length, 5);
  assert.ok(findings.some((x) => x.id === 'permissive-accept'), 'the catch-all ACCEPT opens the box too');
});

// --- recent-one-way ----------------------------------------------------------

test('recent-one-way: a reader without a writer is constant-false, and names the missing --set half', () => {
  const rs = [
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 4 --name SSH -j DROP',
    '-A INPUT -p tcp --dport 22 -j ACCEPT',
    'COMMIT',
  ].join('\n');
  const f = FS.lint(FS.parse(rs)).findings.filter((x) => x.id === 'recent-one-way');
  assert.equal(f.length, 1);
  assert.equal(f[0].severity, 'warning');
  assert.match(f[0].title, /--update consults list "SSH"/);
  assert.match(f[0].title, /can never match/);
  assert.match(f[0].details, /--set --name SSH/);
});

test('recent-one-way: a writer without a reader is bookkeeping nothing consults', () => {
  const rs = [
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -p udp --dport 51820 -m conntrack --ctstate NEW -m recent --set --name WG',
    '-A INPUT -p udp --dport 51820 -j ACCEPT',
    'COMMIT',
  ].join('\n');
  const f = FS.lint(FS.parse(rs)).findings.filter((x) => x.id === 'recent-one-way');
  assert.equal(f.length, 1);
  assert.match(f[0].title, /--set fills list "WG"/);
  assert.match(f[0].details, /--update --seconds 60 --hitcount 4 --name WG/);
});

test('recent-one-way stays silent when both halves exist, and rules without --name pair on DEFAULT', () => {
  const paired = [
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set --name SSH',
    '-A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 4 --name SSH -j DROP',
    '-A INPUT -p tcp --dport 2222 -m conntrack --ctstate NEW -m recent --set',
    '-A INPUT -p tcp --dport 2222 -m conntrack --ctstate NEW -m recent --rcheck --seconds 60 --hitcount 4 -j DROP',
    'COMMIT',
  ].join('\n');
  const f = FS.lint(FS.parse(paired)).findings.filter((x) => x.id === 'recent-one-way');
  assert.equal(f.length, 0);
});

test('recent-one-way: two names do not cover for each other', () => {
  const rs = [
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -p tcp --dport 22 -m recent --set --name SSH',
    '-A INPUT -p tcp --dport 22 -m recent --update --seconds 60 --hitcount 4 --name SSHD -j DROP',
    'COMMIT',
  ].join('\n');
  const f = FS.lint(FS.parse(rs)).findings.filter((x) => x.id === 'recent-one-way');
  assert.equal(f.length, 2);
});

test('recent-one-way: a negated orphan check is called out as constant-TRUE', () => {
  const rs = [
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -p tcp --dport 22 -m recent ! --rcheck --seconds 60 --name KNOCK -j ACCEPT',
    'COMMIT',
  ].join('\n');
  const f = FS.lint(FS.parse(rs)).findings.filter((x) => x.id === 'recent-one-way');
  assert.equal(f.length, 1);
  assert.match(f[0].title, /matches every packet/);
  assert.match(f[0].details, /constant-TRUE/);
});

test('the paired SSH limiter in the accept-all sample stays silent', () => {
  assert.ok(!lintIds('iptables-accept-all-dead.txt').has('recent-one-way'));
});

// --- port-match-without-protocol ---------------------------------------------

test('port-match-without-protocol: --dport with no -p is an error naming the whole-ruleset failure', () => {
  const rs = [
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT --dport 22 -j ACCEPT',
    'COMMIT',
  ].join('\n');
  const f = FS.lint(FS.parse(rs)).findings.filter((x) => x.id === 'port-match-without-protocol');
  assert.equal(f.length, 1);
  assert.equal(f[0].severity, 'error');
  assert.match(f[0].title, /`--dport` with no `-p tcp`/);
  assert.match(f[0].details, /whole ruleset|ENTIRE ruleset|atomic|ATOMIC/i);
});

test('port-match-without-protocol: multiport --dports and --sport are caught too', () => {
  const rs = [
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -m multiport --dports 80,443 -j ACCEPT',
    '-A INPUT --sport 53 -j ACCEPT',
    'COMMIT',
  ].join('\n');
  const f = FS.lint(FS.parse(rs)).findings.filter((x) => x.id === 'port-match-without-protocol');
  assert.equal(f.length, 2);
  assert.ok(f.some((x) => /--dports/.test(x.title)));
  assert.ok(f.some((x) => /--sport/.test(x.title)));
});

test('port-match-without-protocol stays silent when the protocol is present (any -p)', () => {
  const rs = [
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -p tcp --dport 22 -j ACCEPT',
    '-A INPUT -p udp --sport 53 -j ACCEPT',
    '-A INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT',
    'COMMIT',
  ].join('\n');
  const f = FS.lint(FS.parse(rs)).findings.filter((x) => x.id === 'port-match-without-protocol');
  assert.equal(f.length, 0);
});

test('port-match-without-protocol does not fire on rules with no port match at all', () => {
  const rs = [
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -i lo -j ACCEPT',
    '-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT',
    'COMMIT',
  ].join('\n');
  const f = FS.lint(FS.parse(rs)).findings.filter((x) => x.id === 'port-match-without-protocol');
  assert.equal(f.length, 0);
});

test('port-match-without-protocol is iptables-only (nft expresses port and protocol together)', () => {
  const nft = [
    'table inet filter {',
    '  chain input {',
    '    type filter hook input priority 0; policy drop;',
    '    tcp dport 22 accept',
    '  }',
    '}',
  ].join('\n');
  const f = FS.lint(FS.parse(nft)).findings.filter((x) => x.id === 'port-match-without-protocol');
  assert.equal(f.length, 0);
});

// --- reject-type-mismatch ----------------------------------------------------
// Measured in a NET_ADMIN container (iptables 1.8.11, legacy AND nf_tables
// backends): `--reject-with tcp-reset` on a rule not pinned to `-p tcp`
// passes `iptables-restore --test` and FAILS the real commit — the whole
// (atomic) ruleset with it. Cross-family ICMP names fail in the parser.
// nft -c: "you cannot use tcp reset with this protocol" / "conflicting
// protocols specified: ip vs ip6"; the bare `reject with tcp reset` and
// `icmp type` inside `inet` are accepted.

function rejectHits(text) {
  return FS.lint(FS.parse(text)).findings.filter((x) => x.id === 'reject-type-mismatch');
}

test('reject-type-mismatch: the catch-all `-j REJECT --reject-with tcp-reset` (no -p) is an error naming the --test lie', () => {
  const rs = ['*filter', ':INPUT DROP [0:0]', '-A INPUT -p tcp --dport 22 -j ACCEPT', '-A INPUT -j REJECT --reject-with tcp-reset', 'COMMIT'].join('\n');
  const f = rejectHits(rs);
  assert.equal(f.length, 1);
  assert.equal(f[0].severity, 'error');
  assert.equal(f[0].ruleIdx, 1);
  assert.match(f[0].title, /tcp-reset/);
  assert.match(f[0].title, /no `-p` at all/);
  assert.match(f[0].details, /--test/);
  assert.match(f[0].details, /ATOMIC|atomic/);
});

test('reject-type-mismatch: tcp-reset on another protocol or on `! -p tcp` fires; -p tcp / -p 6 / tcp-rst on tcp stay silent', () => {
  const rs = [
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -p udp --dport 53 -j REJECT --reject-with tcp-reset',
    '-A INPUT ! -p tcp -j REJECT --reject-with tcp-reset',
    '-A INPUT -p tcp --dport 113 -j REJECT --reject-with tcp-reset',
    '-A INPUT -p 6 -j REJECT --reject-with tcp-reset',
    '-A INPUT -p tcp -j REJECT --reject-with tcp-rst',
    'COMMIT',
  ].join('\n');
  const f = rejectHits(rs);
  assert.deepEqual(JSON.parse(JSON.stringify(f.map((x) => x.ruleIdx))), [0, 1]); // findings live in the vm realm: compare by value
  assert.match(f[0].title, /`-p udp`/);
  assert.match(f[1].title, /! -p tcp/);
});

test('reject-type-mismatch: a bare -j REJECT and the valid ICMP types of the family never fire', () => {
  const v4 = ['*filter', ':INPUT DROP [0:0]',
    '-A INPUT -j REJECT',
    '-A INPUT -p udp -j REJECT --reject-with icmp-port-unreachable',
    '-A INPUT -j REJECT --reject-with icmp-admin-prohibited',
    'COMMIT'].join('\n');
  assert.equal(rejectHits(v4).length, 0);
  const v6 = ['*filter', ':INPUT DROP [0:0]',
    '-A INPUT -p udp -j REJECT --reject-with icmp6-port-unreachable',
    '-A INPUT -j REJECT --reject-with port-unreach',
    '-A INPUT -j REJECT --reject-with adm-prohibited',
    '-A INPUT -p tcp -j REJECT --reject-with tcp-reset',
    'COMMIT'].join('\n');
  const r6 = FS.parse(v6, { format: 'ip6tables' });
  assert.equal(r6.format, 'ip6tables');
  assert.equal(FS.lint(r6).findings.filter((x) => x.id === 'reject-type-mismatch').length, 0);
});

test('reject-type-mismatch: an ip6tables name under iptables (and vice versa) is an error that names the other tool', () => {
  const v4 = ['*filter', ':INPUT DROP [0:0]', '-A INPUT -p tcp --dport 3306 -j REJECT --reject-with icmp6-port-unreachable', 'COMMIT'].join('\n');
  const f4 = rejectHits(v4);
  assert.equal(f4.length, 1);
  assert.match(f4[0].title, /not a iptables reject type \(it is ip6tables's\)/);
  assert.match(f4[0].details, /unknown reject type "icmp6-port-unreachable"/);
  const v6 = ['*filter', ':INPUT DROP [0:0]', '-A INPUT -p tcp -j REJECT --reject-with icmp-port-unreachable', 'COMMIT'].join('\n');
  const f6 = FS.lint(FS.parse(v6, { format: 'ip6tables' })).findings.filter((x) => x.id === 'reject-type-mismatch');
  assert.equal(f6.length, 1);
  assert.match(f6[0].title, /it is iptables's/);
});

test('reject-type-mismatch: a misspelled reject type is an error too (same parser failure), without a family claim', () => {
  const rs = ['*filter', ':INPUT DROP [0:0]', '-A INPUT -j REJECT --reject-with icmp-port-unreach', 'COMMIT'].join('\n');
  const f = rejectHits(rs);
  assert.equal(f.length, 1);
  assert.doesNotMatch(f[0].title, /it is/);
  assert.match(f[0].details, /no such reject type/);
});

test('reject-type-mismatch: ipv6 tcp-reset on a non-tcp rule fires the same way', () => {
  const v6 = ['*filter', ':INPUT DROP [0:0]', '-A INPUT -p udp -j REJECT --reject-with tcp-reset', 'COMMIT'].join('\n');
  const f = FS.lint(FS.parse(v6, { format: 'ip6tables' })).findings.filter((x) => x.id === 'reject-type-mismatch');
  assert.equal(f.length, 1);
  assert.match(f[0].title, /`-p udp`/);
});

function nftChain(family, ...rules) {
  return [`table ${family} f {`, '  chain input {', '    type filter hook input priority 0; policy drop;', ...rules.map((r) => `    ${r}`), '  }', '}'].join('\n');
}

test('reject-type-mismatch (nft): tcp reset on a udp/icmp rule fires; tcp-pinned and bare forms stay silent', () => {
  const f = rejectHits(nftChain('inet',
    'udp dport 53 reject with tcp reset',
    'ip protocol udp reject with tcp reset',
    'meta l4proto sctp reject with tcp reset',
    'icmp type echo-request reject with tcp reset',
    'tcp dport 22 reject with tcp reset',
    'meta l4proto tcp reject with tcp reset',
    'reject with tcp reset',
    'reject'));
  assert.deepEqual(JSON.parse(JSON.stringify(f.map((x) => x.ruleIdx))), [0, 1, 2, 3]);
  assert.match(f[0].title, /`udp` rule/);
  assert.match(f[1].title, /`udp` rule/);
  assert.match(f[2].title, /`sctp` rule/);
  assert.match(f[3].title, /`icmp` rule/);
  assert.match(f[0].details, /you cannot use tcp reset with this protocol/);
});

test('reject-type-mismatch (nft): icmpv6 type in table ip and icmp type in table ip6 fire; inet and icmpx never do', () => {
  assert.equal(rejectHits(nftChain('ip', 'reject with icmpv6 type port-unreachable')).length, 1);
  assert.match(rejectHits(nftChain('ip', 'reject with icmpv6 type port-unreachable'))[0].title, /conflicting protocols/);
  assert.equal(rejectHits(nftChain('ip6', 'reject with icmp type port-unreachable')).length, 1);
  assert.equal(rejectHits(nftChain('ip', 'reject with icmp type port-unreachable')).length, 0);
  assert.equal(rejectHits(nftChain('ip6', 'reject with icmpv6 type port-unreachable')).length, 0);
  assert.equal(rejectHits(nftChain('inet', 'reject with icmp type port-unreachable', 'reject with icmpv6 type port-unreachable', 'reject with icmpx type port-unreachable')).length, 0);
});

test('nft parser: `reject with …` is a REJECT verdict carrying its type (it used to leave the rule with no action)', () => {
  const r = FS.parse(nftChain('inet', 'udp dport 53 reject with tcp reset', 'reject with icmpx type admin-prohibited', 'tcp dport 22 reject'));
  const rules = r.tables[0].chains[0].rules;
  assert.equal(rules[0].action, 'REJECT');
  assert.equal(rules[0].actionDetail, 'tcp reset');
  assert.equal(rules[0].match, 'udp dport 53');
  assert.equal(rules[1].action, 'REJECT');
  assert.equal(rules[1].actionDetail, 'icmpx type admin-prohibited');
  assert.equal(rules[2].action, 'REJECT');
  assert.equal(rules[2].actionDetail, null);
});

test('nft parser: l4proto token from ip protocol / ip6 nexthdr / meta l4proto / icmp type, never from a negation', () => {
  const r = FS.parse(nftChain('inet', 'ip protocol udp accept', 'ip6 nexthdr udp accept', 'meta l4proto sctp accept', 'icmpv6 type echo-request accept', 'icmp type echo-request accept', 'meta l4proto != tcp accept', 'tcp dport 22 accept'));
  const rules = r.tables[0].chains[0].rules;
  assert.deepEqual(JSON.parse(JSON.stringify(rules.map((x) => x.tokens.l4proto || null))), ['udp', 'udp', 'sctp', 'icmpv6', 'icmp', null, null]);
  assert.equal(rules[6].tokens.protocol, 'tcp');
});

// --- port-match-protocol-mismatch --------------------------------------------
// Measured with iptables-restore --test (parser errors) and nft -c; see the
// smell's comment for the table. `! -p tcp --dport 22` loads and stays silent.

function pmHits(text, opts) {
  return FS.lint(FS.parse(text, opts)).findings.filter((x) => x.id === 'port-match-protocol-mismatch');
}
function ipt(...rules) { return ['*filter', ':INPUT DROP [0:0]', ...rules, 'COMMIT'].join('\n'); }

test('port-match-protocol-mismatch: a port option on a protocol without ports is an error naming the unknown-option failure', () => {
  const f = pmHits(ipt('-A INPUT -p icmp --dport 80 -j ACCEPT', '-A INPUT -p esp --sport 500 -j ACCEPT', '-A INPUT -p all --dport 80 -j ACCEPT', '-A INPUT -p 1 --dport 80 -j ACCEPT', '-A INPUT -p udplite --dport 80 -j ACCEPT'));
  assert.equal(f.length, 5);
  for (const x of f) {
    assert.equal(x.severity, 'error');
    assert.match(x.details, /unknown option/);
    assert.match(x.details, /ATOMIC/);
  }
  assert.match(f[0].title, /`--dport` with `-p icmp`/);
  assert.match(f[1].title, /`--sport` with `-p esp`/);
});

test('port-match-protocol-mismatch: protocols that carry ports, numeric ones and the negated form stay silent', () => {
  assert.equal(pmHits(ipt(
    '-A INPUT -p tcp --dport 22 -j ACCEPT',
    '-A INPUT -p udp --sport 53 -j ACCEPT',
    '-A INPUT -p sctp --dport 3868 -j ACCEPT',
    '-A INPUT -p dccp --dport 5004 -j ACCEPT',
    '-A INPUT -p 17 --dport 53 -j ACCEPT',
    '-A INPUT -p 6 --sport 1024 -j ACCEPT',
    '-A INPUT ! -p tcp --dport 22 -j DROP',
    '-A INPUT -p icmp --icmp-type echo-request -j ACCEPT',
  )).length, 0);
});

test('port-match-protocol-mismatch: no -p at all is the sibling smell, not this one', () => {
  const rs = ipt('-A INPUT --dport 22 -j ACCEPT');
  assert.equal(pmHits(rs).length, 0);
  assert.equal(FS.lint(FS.parse(rs)).findings.filter((x) => x.id === 'port-match-without-protocol').length, 1);
});

test('port-match-protocol-mismatch: an explicit -m for another protocol names the extension that refuses', () => {
  const f = pmHits(ipt('-A INPUT -p tcp -m udp --dport 53 -j ACCEPT', '-A INPUT -p icmp -m tcp --dport 80 -j ACCEPT', '-A INPUT -p 6 -m tcp --dport 22 -j ACCEPT', '-A INPUT -p udp -m udp --dport 53 -j ACCEPT'));
  assert.equal(f.length, 2);
  assert.match(f[0].title, /`-m udp` with `-p tcp`/);
  assert.match(f[0].details, /UDP match requires '-p udp'/);
  assert.match(f[1].title, /`-m tcp` with `-p icmp`/);
});

test('port-match-protocol-mismatch: multiport on a port-less protocol fires; on udp, udplite and tcp it does not', () => {
  const f = pmHits(ipt('-A INPUT -p icmp -m multiport --dports 123,161 -j ACCEPT', '-A INPUT -p udp -m multiport --dports 53,123 -j ACCEPT', '-A INPUT -p udplite -m multiport --sports 53 -j ACCEPT', '-A INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT'));
  assert.equal(f.length, 1);
  assert.match(f[0].title, /`--dports` \(multiport\) with `-p icmp`/);
  assert.match(f[0].details, /multiport only works with TCP, UDP, UDPLITE, SCTP and DCCP/);
});

test('port-match-protocol-mismatch: ip6tables refuses ports on ipv6-icmp/icmpv6 the same way', () => {
  const f = pmHits(ipt('-A INPUT -p ipv6-icmp --dport 80 -j ACCEPT', '-A INPUT -p icmpv6 --sport 80 -j ACCEPT', '-A INPUT -p tcp --dport 22 -j ACCEPT'), { format: 'ip6tables' });
  assert.equal(f.length, 2);
  assert.match(f[0].title, /`-p ipv6-icmp`/);
});

test('port-match-protocol-mismatch (nft): two transport protocols in one rule fire; same-protocol pairs and the set form stay silent', () => {
  const f = pmHits(nftChain('inet',
    'meta l4proto udp tcp dport 22 accept',
    'ip protocol udp tcp dport 22 accept',
    'udp dport 53 tcp dport 22 accept',
    'icmp type echo-request udp dport 53 accept',
    'icmpv6 type echo-request tcp dport 22 accept',
    'meta l4proto tcp tcp dport 22 accept',
    'ip protocol tcp tcp dport 22 accept',
    'tcp dport 22 tcp sport 1024-65535 accept',
    'meta l4proto { tcp, udp } th dport 53 accept',
    'meta l4proto sctp sctp dport 80 accept'));
  assert.deepEqual(JSON.parse(JSON.stringify(f.map((x) => x.ruleIdx))), [0, 1, 2, 3, 4]);
  assert.match(f[0].title, /`udp` and `tcp` in one rule/);
  assert.match(f[3].details, /conflicting transport layer protocols specified: icmp vs\. udp/);
  assert.match(f[0].details, /meta l4proto \{ tcp, udp \} th dport 53/);
});

// --- nat-state-match-dead ----------------------------------------------------
// Measured: nat sees only the NEW packet of a connection — 3/0/0/0 packets on
// NEW / ESTABLISHED,RELATED / INVALID / unconditional rules in a nat chain
// after three connections, against 3/10 for the same pair in filter.

function natHits(text) {
  return FS.lint(FS.parse(text)).findings.filter((x) => x.id === 'nat-state-match-dead');
}

test('nat-state-match-dead: ESTABLISHED,RELATED and INVALID matches in nat are dead rules, warnings that name the mechanism', () => {
  const rs = ['*nat', ':PREROUTING ACCEPT [0:0]', ':POSTROUTING ACCEPT [0:0]',
    '-A PREROUTING -m conntrack --ctstate INVALID -j DROP',
    '-A PREROUTING -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT',
    '-A PREROUTING -i eth0 -p tcp --dport 80 -j DNAT --to-destination 10.0.0.10:80',
    '-A POSTROUTING -m state --state ESTABLISHED -j ACCEPT',
    'COMMIT'].join('\n');
  const f = natHits(rs);
  assert.deepEqual(JSON.parse(JSON.stringify(f.map((x) => [x.chain, x.ruleIdx]))), [['PREROUTING', 0], ['PREROUTING', 1], ['POSTROUTING', 0]]);
  for (const x of f) {
    assert.equal(x.severity, 'warning');
    assert.match(x.details, /3 packets on the NEW rule and 0/);
  }
  assert.match(f[0].title, /`--ctstate INVALID` in the nat table can never match/);
  assert.match(f[2].title, /`--state ESTABLISHED`/);
});

test('nat-state-match-dead: a set that includes NEW, a negated match and the filter table are left alone', () => {
  const rs = ['*nat', ':PREROUTING ACCEPT [0:0]', ':POSTROUTING ACCEPT [0:0]',
    '-A POSTROUTING -o eth0 -m conntrack --ctstate NEW,ESTABLISHED -j MASQUERADE',
    '-A PREROUTING -m conntrack --ctstate NEW -p tcp --dport 80 -j DNAT --to-destination 10.0.0.10:80',
    '-A PREROUTING ! --ctstate ESTABLISHED -j ACCEPT',
    'COMMIT',
    '*filter', ':INPUT DROP [0:0]',
    '-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT',
    '-A INPUT -m conntrack --ctstate INVALID -j DROP',
    'COMMIT'].join('\n');
  assert.equal(natHits(rs).length, 0);
});

test('nat-state-match-dead (nft): ct state in a type nat chain fires; the same in a filter chain does not', () => {
  const nft = ['table ip n {', '  chain pre {', '    type nat hook prerouting priority -100;', '    ct state established,related accept', '    ct state invalid drop', '    ct state new tcp dport 80 dnat to 10.0.0.10', '  }', '  chain post {', '    type nat hook postrouting priority 100;', '    ct state new,established masquerade', '  }', '  chain in {', '    type filter hook input priority 0; policy drop;', '    ct state established,related accept', '  }', '}'].join('\n');
  const f = natHits(nft);
  assert.deepEqual(JSON.parse(JSON.stringify(f.map((x) => [x.chain, x.ruleIdx]))), [['pre', 0], ['pre', 1]]);
  assert.match(f[0].title, /`ct state established,related` in the nat table can never match/);
});

test('nft parser: chains carry their type (nat / filter)', () => {
  const nft = ['table ip n {', '  chain pre {', '    type nat hook prerouting priority -100;', '    accept', '  }', '  chain in {', '    type filter hook input priority 0;', '    accept', '  }', '}'].join('\n');
  const r = FS.parse(nft);
  assert.deepEqual(JSON.parse(JSON.stringify(r.tables[0].chains.map((c) => [c.name, c.type, c.hook]))), [['pre', 'nat', 'prerouting'], ['in', 'filter', 'input']]);
});

// --- tcp-flags-never-match ---------------------------------------------------
// Measured (iptables 1.8.11 / nft 1.1.3): every form loads with rc 0; dead
// rules counted 0 packets over three connections, the negated form took all
// 12 and shadowed the rules after it.

function flagHits(text) {
  return FS.lint(FS.parse(text)).findings.filter((x) => x.id === 'tcp-flags-never-match');
}

test('tcp-flags-never-match: comp flags outside the mask are dead rules (errors naming the flag); the negated form matches everything', () => {
  const rs = ['*filter', ':INPUT DROP [0:0]',
    '-A INPUT -p tcp -m tcp --tcp-flags SYN FIN -j DROP',
    '-A INPUT -p tcp -m tcp --tcp-flags SYN,ACK FIN,SYN,RST,PSH,ACK,URG -j DROP',
    '-A INPUT -p tcp -m tcp --tcp-flags NONE SYN -j DROP',
    '-A INPUT -p tcp -m tcp ! --tcp-flags SYN FIN -j ACCEPT',
    '-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT',
    'COMMIT'].join('\n');
  const f = flagHits(rs);
  assert.deepEqual(JSON.parse(JSON.stringify(f.map((x) => x.ruleIdx))), [0, 1, 2, 3]);
  for (const x of f) assert.equal(x.severity, 'error');
  assert.match(f[0].title, /`--tcp-flags SYN FIN` can never match — FIN is tested but not in the mask/);
  assert.match(f[1].title, /FIN\/RST\/PSH\/URG is tested but not in the mask/);
  assert.match(f[2].title, /`--tcp-flags NONE SYN` can never match/);
  assert.match(f[3].title, /`! --tcp-flags SYN FIN` matches EVERY TCP packet/);
  assert.match(f[3].details, /a DROP here blackholes TCP, an ACCEPT lets everything through/);
  assert.match(f[0].details, /counted 0 packets over three TCP connections/);
});

test('tcp-flags-never-match: comp inside the mask, ALL/NONE patterns, --syn as printed by iptables-save and rules without flags are left alone', () => {
  const rs = ['*filter', ':INPUT DROP [0:0]',
    '-A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN -j DROP',
    '-A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP',
    '-A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,PSH,ACK,URG -j DROP',
    '-A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -m limit --limit 25/s -j ACCEPT',
    '-A INPUT -p tcp -m tcp --tcp-flags SYN,FIN FIN -j DROP',
    '-A INPUT -p tcp -m tcp ! --tcp-flags FIN,SYN,RST,ACK SYN -j ACCEPT',
    '-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT',
    'COMMIT'].join('\n');
  assert.equal(flagHits(rs).length, 0);
});

test('tcp-flags-never-match (nft): `tcp flags & mask == comp` with comp outside the mask fires, `!=` fires as always-true, correct and mask-less forms do not', () => {
  const nft = ['table inet f {', '  chain in {', '    type filter hook input priority 0;',
    '    tcp flags & syn == fin drop',
    '    tcp flags & (syn|ack) == syn|fin drop',
    '    tcp flags & syn != fin accept',
    '    tcp flags & (fin | syn | rst | ack) == syn accept',
    '    tcp flags & (fin|syn) == 0x0 drop',
    '    tcp flags syn accept',
    '    tcp flags == syn accept',
    '    tcp dport 22 accept', '  }', '}'].join('\n');
  const f = flagHits(nft);
  assert.deepEqual(JSON.parse(JSON.stringify(f.map((x) => x.ruleIdx))), [0, 1, 2]);
  assert.match(f[0].title, /`tcp flags & syn == fin` can never match — FIN is tested/);
  assert.match(f[1].title, /`tcp flags & \(syn\|ack\) == syn\|fin` can never match/);
  assert.match(f[2].title, /`tcp flags & syn != fin` matches EVERY TCP packet/);
});

test('parsers: --tcp-flags is a two-argument option (mask, comp, negation); nft records the & mask ==|!= comp form only', () => {
  const ipt = FS.parse(['*filter', ':INPUT DROP [0:0]',
    '-A INPUT -p tcp -m tcp ! --tcp-flags FIN,SYN,RST,ACK SYN -j ACCEPT',
    '-A INPUT -p tcp -m tcp --tcp-flags ALL NONE -j DROP', 'COMMIT'].join('\n'));
  const [r0, r1] = ipt.tables[0].chains[0].rules;
  assert.deepEqual(JSON.parse(JSON.stringify([r0.tokens.tcp_flags_mask, r0.tokens.tcp_flags_comp, r0.tokens.tcp_flags_negated])), ['FIN,SYN,RST,ACK', 'SYN', true]);
  assert.deepEqual(JSON.parse(JSON.stringify([r1.tokens.tcp_flags_mask, r1.tokens.tcp_flags_comp, r1.tokens.tcp_flags_negated])), ['ALL', 'NONE', false]);
  const nft = FS.parse(['table inet f {', '  chain in {', '    type filter hook input priority 0;',
    '    tcp flags & (fin | syn) != syn drop', '    tcp flags syn accept', '  }', '}'].join('\n'));
  const [n0, n1] = nft.tables[0].chains[0].rules;
  assert.deepEqual(JSON.parse(JSON.stringify([n0.tokens.tcp_flags_mask, n0.tokens.tcp_flags_comp, n0.tokens.tcp_flags_negated])), ['(fin | syn)', 'syn', true]);
  assert.equal(n1.tokens.tcp_flags_mask, undefined);
});

test('nat-state-match-dead: a dump with *filter before *nat (the common order) still inspects the nat table (regression: an early return skipped it)', () => {
  const rs = ['*filter', ':INPUT DROP [0:0]', '-A INPUT -p tcp --dport 22 -j ACCEPT', 'COMMIT',
    '*nat', ':PREROUTING ACCEPT [0:0]', '-A PREROUTING -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT', 'COMMIT'].join('\n');
  const f = FS.lint(FS.parse(rs)).findings.filter((x) => x.id === 'nat-state-match-dead');
  assert.deepEqual(JSON.parse(JSON.stringify(f.map((x) => [x.table, x.chain, x.ruleIdx]))), [['nat', 'PREROUTING', 0]]);
});

// --- tcp-option-without-tcp --------------------------------------------------
// Measured (iptables 1.8.11 / nft 1.1.3): --syn/--tcp-flags/--tcp-option under
// a non-tcp -p (or none) die with `unknown option` and iptables-restore loads
// NOTHING; nft refuses `tcp flags` next to a udp/icmp match ("conflicting
// transport layer protocols") but accepts `tcp option` there.

function tcpOptHits(text) {
  return FS.lint(FS.parse(text)).findings.filter((x) => x.id === 'tcp-option-without-tcp');
}

test('tcp-option-without-tcp: --syn / --tcp-flags / --tcp-option under -p udp, -p icmp or no -p are errors that name the option and the protocol', () => {
  const rs = ['*filter', ':INPUT DROP [0:0]',
    '-A INPUT -p udp --syn -j DROP',
    '-A INPUT --syn -j DROP',
    '-A INPUT -p icmp --tcp-flags SYN SYN -j DROP',
    '-A INPUT -p udp --dport 53 --tcp-option 8 -j DROP',
    '-A INPUT -p tcp --syn -j ACCEPT',
    '-A INPUT -p 6 --tcp-flags FIN,SYN,RST,ACK SYN -j ACCEPT',
    '-A INPUT ! -p tcp --syn -j DROP',
    '-A INPUT -p tcp --dport 22 -j ACCEPT',
    'COMMIT'].join('\n');
  const f = tcpOptHits(rs);
  assert.deepEqual(JSON.parse(JSON.stringify(f.map((x) => x.ruleIdx))), [0, 1, 2, 3]);
  for (const x of f) assert.equal(x.severity, 'error');
  assert.match(f[0].title, /`--syn` with -p udp — a TCP-only option/);
  assert.match(f[1].title, /`--syn` with no -p at all/);
  assert.match(f[2].title, /`--tcp-flags` with -p icmp/);
  assert.match(f[3].title, /`--tcp-option` with -p udp/);
  assert.match(f[0].details, /loads NOTHING/);
  assert.match(f[1].details, /Add `-p tcp`/);
});

test('tcp-option-without-tcp (nft): tcp flags next to a udp/icmp transport fires, tcp option does not (measured accepted), tcp-only rules are fine', () => {
  const nft = ['table inet f {', '  chain in {', '    type filter hook input priority 0;',
    '    udp dport 53 tcp flags syn drop',
    '    meta l4proto udp tcp flags syn drop',
    '    ip protocol udp tcp flags & (fin|syn) == syn drop',
    '    icmp type echo-request tcp flags syn drop',
    '    udp dport 53 tcp option maxseg exists drop',
    '    tcp dport 22 tcp flags syn accept',
    '    tcp flags syn accept',
    '    meta l4proto tcp tcp flags syn accept', '  }', '}'].join('\n');
  const f = tcpOptHits(nft);
  assert.deepEqual(JSON.parse(JSON.stringify(f.map((x) => x.ruleIdx))), [0, 1, 2, 3]);
  assert.match(f[0].title, /`tcp flags` next to a udp transport match — nft refuses the rule/);
  assert.match(f[3].title, /next to a icmp transport match/);
  assert.match(f[0].details, /conflicting transport layer protocols specified/);
});

test('tcp-option-without-tcp leaves ufw alone and does not duplicate port-match-protocol-mismatch (-m tcp with -p udp and a port is theirs)', () => {
  const rs = ['*filter', ':INPUT DROP [0:0]',
    '-A INPUT -p udp -m tcp --dport 53 -j ACCEPT',
    'COMMIT'].join('\n');
  assert.equal(tcpOptHits(rs).length, 0);
});
