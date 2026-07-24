// FirewallScope linter — detects common firewall smells on the parsed IR.
// Each finding carries a severity (error / warning / info), a smell id, the
// chain it points at, and (when applicable) the rule index inside that chain.
// All detectors are pure functions over the parser output; the linter never
// reads raw text, only the structured tokens parsed earlier.
(function () {
  'use strict';

  // Ports that should almost never be reachable from the whole internet:
  // remote-access shells, databases, and unauthenticated data/admin services.
  // Accepting any of these from 0.0.0.0/0 is flagged as an error.
  const ADMIN_PORTS = {
    21:    'ftp',
    22:    'ssh',
    23:    'telnet',
    445:   'smb',
    1433:  'mssql',
    2375:  'docker-api',   // Docker daemon without TLS — remote root, trivially
    3306:  'mysql',
    3389:  'rdp',
    5432:  'postgres',
    5900:  'vnc',
    6379:  'redis',
    9200:  'elasticsearch',
    11211: 'memcached',
    27017: 'mongodb'
  };

  function lint(result) {
    const findings = [];
    if (!result || !result.tables || result.error) {
      return { findings: [], counts: zeroCounts(), byKey: {} };
    }

    for (const table of result.tables) {
      const isFilterTable = isFilterTableName(table.name);
      for (const chain of table.chains) {
        if (isFilterTable && isBuiltInInputChain(chain, result.format)) {
          flagMissingInputDrop(chain, table, findings);
          flagLoopbackNotAllowed(chain, table, findings);
          flagMissingLoopbackSpoofDrop(chain, table, findings, result.format);
          flagMissingEstablishedAccept(chain, table, findings, result.format);
          flagIcmpv6Blocked(chain, table, findings, result.format);
        }
        if (isFilterTable && isBuiltInForwardChain(chain, result.format)) {
          flagForwardNoDefaultDeny(chain, table, findings);
        }
        if (isFilterTable &&
            (isBuiltInInputChain(chain, result.format) || isBuiltInForwardChain(chain, result.format))) {
          flagDropWithoutLog(chain, table, findings, result.format);
          flagMissingInvalidDrop(chain, table, findings, result.format);
        }
        scanChainRules(chain, table, findings);
        if (isFilterTable) {
          detectOverbroadSource(chain, table, findings);
          detectBogonSourceAccept(chain, table, findings);
          detectMacBasedTrust(chain, table, findings, result.format);
          detectAdminPortNoRateLimit(chain, table, findings, result.format);
        }
        detectUnlimitedLog(chain, table, findings, result.format);
        detectLogTcpSequence(chain, table, findings, result.format);
        if (isFilterTable) {
          detectUnlimitedIcmpEcho(chain, table, findings, result.format);
        }
        detectDuplicateRules(chain, table, findings, result.format);
        detectShadowedRules(chain, table, findings, result.format);
        detectRuleAfterPolicyDrop(chain, table, findings);
        if (isFilterTable) {
          detectFallthroughAccept(result, chain, table, result.format, findings);
        }
        if (isNatPreroutingChain(table, chain, result.format)) {
          detectExposedViaDnat(table, chain, findings);
        }
        if (isNatPostroutingChain(table, chain, result.format)) {
          detectMasqueradeAnySource(table, chain, findings);
        }
      }
      detectUnusedChains(table, findings, result.format);
      if (isFilterTable) {
        detectUnrestrictedEgress(table, findings, result.format);
      }
    }

    if (result.format === 'nftables') {
      detectIpv6Unfiltered(result, findings);
    }
    detectDnatForwardBlocked(result, findings);

    return summarize(findings);
  }

  // A DNAT in nat/PREROUTING rewrites the packet BEFORE the filter table
  // sees it — but the rewritten packet still has to survive FORWARD. Publish
  // :2222 -> 10.0.0.20:22 and forget the matching `FORWARD -d 10.0.0.20
  // --dport 22 ACCEPT`, and a deny-postured FORWARD silently drops it: the
  // port-forward looks configured, the service is dark, and the operator
  // debugs the DNAT for an hour. The exact opposite failure of
  // exposed-via-dnat (there the forward WORKS and exposes an admin port) —
  // they compose: a sample can trip one, the other, or neither.
  //
  // Fires only when FORWARD is deny-postured (an open FORWARD forwards
  // everything, nothing is blocked) and no ACCEPT rule covers the target.
  // Conservative: a conntrack ESTABLISHED/RELATED rule doesn't count (the
  // first forwarded packet is NEW), but any accept whose destination and
  // port cover the target suppresses the finding — including ones with
  // matches we don't model, so we never cry "blocked" over a rule we can't
  // fully read. REDIRECT and DNAT-to-localhost are skipped: they don't
  // forward anywhere.
  function detectDnatForwardBlocked(result, findings) {
    if (!window.FirewallScope || typeof window.FirewallScope.extractDnatRewrite !== 'function') return;
    const extract = window.FirewallScope.extractDnatRewrite;
    const tables = result.tables || [];
    const format = result.format;

    let fwd = null;
    for (const table of tables) {
      if (!isFilterTableName(table.name)) continue;
      fwd = (table.chains || []).find((c) => isBuiltInForwardChain(c, format));
      if (fwd) break;
    }
    if (!fwd) return; // no FORWARD chain visible → can't reason about it
    const denyPosture =
      isDropPolicy(fwd.policy) || isRejectPolicy(fwd.policy) || hasFinalCatchAllDrop(fwd);
    if (!denyPosture) return;

    for (const table of tables) {
      for (const chain of table.chains || []) {
        if (!isNatPreroutingChain(table, chain, format)) continue;
        const rules = chain.rules || [];
        for (let i = 0; i < rules.length; i++) {
          const rule = rules[i];
          if (String(rule.action || '').toUpperCase() !== 'DNAT') continue;
          const rw = extract(rule);
          if (!rw || !rw.destination || rw.dport == null) continue;
          if (rw.destination === '127.0.0.1') continue; // local, not forwarded
          if (forwardCoversTarget(fwd, rw.destination, rw.dport)) continue;
          findings.push({
            id: 'dnat-forward-blocked',
            severity: 'warning',
            table: table.name,
            tableFamily: table.family || null,
            chain: chain.name,
            ruleIdx: i,
            title: `Port-forward to ${rw.destination}:${rw.dport} is dropped by FORWARD`,
            details: `This DNAT rewrites to ${rw.destination}:${rw.dport}, but the deny-postured FORWARD chain has no ACCEPT rule for that destination and port — the rewritten packet is dropped and the forward never works. Add \`FORWARD -d ${rw.destination} -p tcp --dport ${rw.dport} -j ACCEPT\` (nft: \`ip daddr ${rw.destination} tcp dport ${rw.dport} accept\`).`
          });
        }
      }
    }
  }

  // A conntrack rule that only accepts existing flows can't be what lets a
  // freshly-forwarded (NEW) connection through.
  function isEstablishedOnlyRule(rule) {
    const raw = String(rule.raw || '');
    const m = raw.match(/(?:--ctstate|ct\s+state)\s+([A-Za-z,]+)/i);
    if (!m) return false;
    const states = m[1].toUpperCase();
    return /ESTABLISHED|RELATED/.test(states) && !/\bNEW\b/.test(states);
  }

  // Does some ACCEPT rule in FORWARD let a NEW connection to destIp:dport
  // through? Destination and port use the same subset arithmetic as
  // shadowed-rule; an unconstrained field covers everything.
  function forwardCoversTarget(fwd, destIp, dport) {
    for (const rule of fwd.rules || []) {
      if (!isAcceptAction(rule)) continue;
      if (isEstablishedOnlyRule(rule)) continue;
      const t = rule.tokens || {};
      if (!cidrSubsetOrAny(destIp, t.destination)) continue;
      if (!portSubsetOrAny(String(dport), t.dport)) continue;
      return true;
    }
    return false;
  }

  // IPv6 is the forgotten front door: nftables families are independent
  // pipelines, so a carefully deny-postured `table ip` filters ONLY IPv4 —
  // every dual-stack service is still reachable over the address the LAN's
  // router advertisements handed each host, and attackers scan v6 too.
  // Fires only for nftables pastes: an iptables-save dump can't show the
  // other family (ip6tables may well be fine), and ufw manages both stacks
  // itself. Only when some family-ip input hook is deny-postured — that
  // posture proves filtering was intended, so its absence for v6 is almost
  // never a choice. If an ip6/inet input hook EXISTS but is wide open,
  // missing-input-drop already says the important thing about that chain.
  function detectIpv6Unfiltered(result, findings) {
    const tables = result.tables || [];
    const denyPosture = (c) =>
      isDropPolicy(c.policy) || isRejectPolicy(c.policy) || hasFinalCatchAllDrop(c);
    let lockedTable = null;
    let lockedChain = null;
    for (const table of tables) {
      if ((table.family || 'ip') !== 'ip') continue;
      const chain = (table.chains || []).find(
        (c) => c.builtIn && c.hook === 'input' && denyPosture(c)
      );
      if (chain) { lockedTable = table; lockedChain = chain; break; }
    }
    if (!lockedTable) return;
    const v6Covered = tables.some(
      (t) =>
        (t.family === 'ip6' || t.family === 'inet') &&
        (t.chains || []).some((c) => c.builtIn && c.hook === 'input')
    );
    if (v6Covered) return;
    findings.push({
      id: 'ipv6-unfiltered',
      severity: 'warning',
      table: lockedTable.name,
      tableFamily: lockedTable.family || null,
      chain: lockedChain.name,
      ruleIdx: null,
      title: 'IPv4 input is filtered but IPv6 is not',
      details: `Table ip ${lockedTable.name} deny-postures its input hook, but no ip6 or inet table hooks input at all. nftables families are independent pipelines: every dual-stack service is reachable over IPv6 unfiltered. Add an inet table (or mirror the rules in a family ip6 table).`
    });
  }

  function flagMissingInputDrop(chain, table, findings) {
    if (isDropPolicy(chain.policy) || isRejectPolicy(chain.policy)) return;
    if (hasFinalCatchAllDrop(chain)) return;
    findings.push({
      id: 'missing-input-drop',
      severity: 'error',
      table: table.name,
      tableFamily: table.family || null,
      chain: chain.name,
      ruleIdx: null,
      title: `Chain ${chain.name} has no default-deny`,
      details: `Policy is ${chain.policy || 'ACCEPT'} and there is no catch-all DROP / REJECT rule at the end. Unmatched packets are accepted.`
    });
  }

  // A dport that opens more than this many ports at once, from any source, is
  // almost always a mistake (e.g. `--dport 1024:65535`). Ordinary app ranges
  // (a few hundred ports) stay under it and are not flagged.
  const WIDE_PORT_THRESHOLD = 1024;

  function scanChainRules(chain, table, findings) {
    const isBuiltIn = chain.builtIn !== false; // many parsers omit the flag for built-ins
    for (let i = 0; i < chain.rules.length; i++) {
      const rule = chain.rules[i];
      if (!isAcceptAction(rule)) continue;
      if (!isSourceAny(rule)) continue;

      // A very wide range subsumes any admin ports it contains, so check it
      // first and report the range rather than a misleading single-port hit.
      const span = dportSpan(rule);
      if (span > WIDE_PORT_THRESHOLD) {
        findings.push({
          id: 'wide-open-port-range',
          severity: 'warning',
          table: table.name,
          tableFamily: table.family || null,
          chain: chain.name,
          ruleIdx: i,
          title: `Accepts a wide port range (${span} ports) from any source`,
          details: rule.raw || ''
        });
        continue;
      }

      const portHit = matchAdminPort(rule);
      if (portHit) {
        findings.push({
          id: 'exposed-admin-port',
          severity: 'error',
          table: table.name,
          tableFamily: table.family || null,
          chain: chain.name,
          ruleIdx: i,
          title: `${portHit.service} (port ${portHit.port}) accepted from any source`,
          details: rule.raw || ''
        });
        continue;
      }

      if (isBuiltIn && hasNoPortRestriction(rule) && !isLoopbackRule(rule) && !isEstablishedRule(rule)) {
        findings.push({
          id: 'permissive-accept',
          severity: 'warning',
          table: table.name,
          tableFamily: table.family || null,
          chain: chain.name,
          ruleIdx: i,
          title: 'Accepts all traffic from any source',
          details: rule.raw || ''
        });
      }
    }
  }

  function isBuiltInInputChain(chain, format) {
    if (format === 'nftables') {
      return chain.builtIn && chain.hook === 'input';
    }
    return chain.name === 'INPUT';
  }

  function isBuiltInForwardChain(chain, format) {
    if (format === 'nftables') {
      return chain.builtIn && chain.hook === 'forward';
    }
    return chain.name === 'FORWARD';
  }

  function isBuiltInOutputChain(chain, format) {
    if (format === 'nftables') {
      return chain.builtIn && chain.hook === 'output';
    }
    return chain.name === 'OUTPUT';
  }

  // A locked-down INPUT next to a wide-open OUTPUT is what post-compromise
  // tooling counts on: reverse shells, exfiltration and C2 beacons all dial
  // *out*, and ingress filtering never sees them. Flagged only when some
  // INPUT-like chain in the same table has a deny posture — on a firewall
  // open in both directions, missing-input-drop already says the important
  // thing and this would be noise on top. Info severity: egress filtering is
  // defense in depth, not an open door.
  function detectUnrestrictedEgress(table, findings, format) {
    const chains = table.chains || [];
    const denyPosture = (c) =>
      isDropPolicy(c.policy) || isRejectPolicy(c.policy) || hasFinalCatchAllDrop(c);
    const lockedInput = chains.find((c) => isBuiltInInputChain(c, format) && denyPosture(c));
    if (!lockedInput) return;
    for (const chain of chains) {
      if (!isBuiltInOutputChain(chain, format)) continue;
      if (denyPosture(chain)) continue;
      findings.push({
        id: 'unrestricted-egress',
        severity: 'info',
        table: table.name,
        tableFamily: table.family || null,
        chain: chain.name,
        ruleIdx: null,
        title: `${lockedInput.name} is locked down but egress is unrestricted`,
        details: `${chain.name} has policy ${chain.policy || 'ACCEPT'} and no catch-all deny, so any process on this host can connect out anywhere. Ingress filtering does not stop what already runs inside — consider egress filtering: allow loopback, ESTABLISHED, DNS/NTP and the destinations the host actually needs, then default-deny the rest.`
      });
    }
  }

  // FORWARD with policy ACCEPT and no catch-all deny routes anything between
  // any interfaces the moment ip_forward is on — the classic way a Docker or
  // VPN host quietly becomes an open router. Warning rather than error: on a
  // non-routing host (ip_forward=0) the chain never sees a packet, which the
  // ruleset alone can't tell us.
  function flagForwardNoDefaultDeny(chain, table, findings) {
    if (isDropPolicy(chain.policy) || isRejectPolicy(chain.policy)) return;
    if (hasFinalCatchAllDrop(chain)) return;
    findings.push({
      id: 'forward-no-default-deny',
      severity: 'warning',
      table: table.name,
      tableFamily: table.family || null,
      chain: chain.name,
      ruleIdx: null,
      title: `Chain ${chain.name} routes anything — no default-deny`,
      details: `Policy is ${chain.policy || 'ACCEPT'} and there is no catch-all DROP / REJECT rule. If IP forwarding is enabled, this host forwards traffic between any networks it can reach.`
    });
  }

  // A deny-posture INPUT without an ESTABLISHED,RELATED accept drops the
  // replies to the host's own outbound connections — DNS answers, apt/dnf
  // downloads, everything. Skipped for ufw: its iptables backend inserts the
  // conntrack rule automatically and `ufw status` never shows it.
  function flagMissingEstablishedAccept(chain, table, findings, format) {
    if (format === 'ufw') return;
    const hasDenyPosture =
      isDropPolicy(chain.policy) ||
      isRejectPolicy(chain.policy) ||
      hasFinalCatchAllDrop(chain);
    if (!hasDenyPosture) return;
    const allowsEstablished = (chain.rules || []).some(r => isAcceptAction(r) && isEstablishedRule(r));
    if (allowsEstablished) return;
    findings.push({
      id: 'missing-established-accept',
      severity: 'warning',
      table: table.name,
      tableFamily: table.family || null,
      chain: chain.name,
      ruleIdx: null,
      title: `${chain.name} has default-deny but never accepts ESTABLISHED traffic`,
      details: 'No `-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT` (or nft `ct state established,related accept`) rule found. Replies to this host\'s own outbound connections (DNS answers, package downloads) will be dropped.'
    });
  }

  // A user-defined chain that no packet can ever reach is dead configuration —
  // and worse than clutter: an ACCEPT sitting in an unwired chain reads as if
  // it were active. Reachability is computed by BFS from the built-in chains
  // (following jump/goto within the table), so a chain referenced only by
  // another dead chain is flagged too. Skipped for ufw (its status output has
  // no user chains) and for tables with no built-in chain at all (a partial
  // paste — reachability can't be reasoned about).
  function detectUnusedChains(table, findings, format) {
    if (format === 'ufw') return;
    const chains = table.chains || [];
    const byName = new Map(chains.map(c => [c.name, c]));
    const visited = new Set();
    const queue = [];
    for (const chain of chains) {
      if (chain.builtIn === true) {
        visited.add(chain.name);
        queue.push(chain);
      }
    }
    if (queue.length === 0) return;
    while (queue.length) {
      const chain = queue.shift();
      for (const rule of chain.rules || []) {
        if (!rule.isJumpToChain || !rule.action) continue;
        const target = byName.get(rule.action);
        if (target && !visited.has(target.name)) {
          visited.add(target.name);
          queue.push(target);
        }
      }
    }
    for (const chain of chains) {
      if (visited.has(chain.name)) continue;
      const ruleCount = (chain.rules || []).length;
      findings.push({
        id: 'unused-chain',
        severity: ruleCount > 0 ? 'warning' : 'info',
        table: table.name,
        tableFamily: table.family || null,
        chain: chain.name,
        ruleIdx: null,
        title: `Chain ${chain.name} is never reached`,
        details: ruleCount > 0
          ? `No reachable chain jumps to ${chain.name}, so its ${ruleCount} rule${ruleCount === 1 ? '' : 's'} never see a packet. If they were meant to be active, the jump is missing; if not, the chain is dead weight.`
          : `Defined but empty and never jumped to — dead configuration, safe to delete.`
      });
    }
  }

  // An IPv6 default-deny INPUT that never accepts ICMPv6 doesn't harden the
  // host — it breaks it. Neighbor Discovery (the IPv6 replacement for ARP)
  // runs over ICMPv6, so dropping it kills address resolution, SLAAC and
  // router discovery; Path MTU Discovery dies with it (IPv6 routers never
  // fragment, so black-holed big packets just hang). Skipped for ufw (its
  // before6.rules accepts ICMPv6 invisibly) and for plain iptables (an
  // IPv4-only ruleset says nothing about the host's IPv6 posture).
  function flagIcmpv6Blocked(chain, table, findings, format) {
    if (format === 'ufw' || format === 'iptables') return;
    if (format === 'nftables') {
      const fam = String(table.family || '').toLowerCase();
      if (fam !== 'ip6' && fam !== 'inet') return;
    }
    const hasDenyPosture =
      isDropPolicy(chain.policy) ||
      isRejectPolicy(chain.policy) ||
      hasFinalCatchAllDrop(chain);
    if (!hasDenyPosture) return;
    if (chainAcceptsIcmpv6(chain, table, new Set())) return;
    findings.push({
      id: 'icmpv6-blocked',
      severity: 'error',
      table: table.name,
      tableFamily: table.family || null,
      chain: chain.name,
      ruleIdx: null,
      title: `${chain.name} default-denies IPv6 but never accepts ICMPv6`,
      details: 'IPv6 needs ICMPv6 to function: Neighbor Discovery (the ARP replacement) and Path MTU Discovery both run over it. Blocking it breaks address resolution and black-holes large packets. Add `-p ipv6-icmp -j ACCEPT` (nft: `meta l4proto ipv6-icmp accept`) before the deny.'
    });
  }

  // True if the chain — or any chain it jumps to, followed recursively within
  // the same table — has an ACCEPT that matches ICMPv6.
  function chainAcceptsIcmpv6(chain, table, seen) {
    if (seen.has(chain.name)) return false;
    seen.add(chain.name);
    for (const rule of chain.rules || []) {
      if (isAcceptAction(rule) && isIcmpv6Rule(rule)) return true;
      if (rule.isJumpToChain && rule.action) {
        const target = (table.chains || []).find(c => c.name === rule.action);
        if (target && chainAcceptsIcmpv6(target, table, seen)) return true;
      }
    }
    return false;
  }

  function isIcmpv6Rule(rule) {
    const proto = String((rule.tokens && rule.tokens.protocol) || '').toLowerCase();
    if (proto === 'icmpv6' || proto === 'ipv6-icmp' || proto === 'icmp6') return true;
    // nftables spellings never land in tokens.protocol: `ip6 nexthdr icmpv6`,
    // `meta l4proto ipv6-icmp`, `icmpv6 type ...`
    const text = `${rule.raw || ''} ${rule.match || ''}`;
    return /icmpv6|ipv6-icmp|icmp6/i.test(text);
  }

  // Only the filter table (and its variants across formats) actually drops
  // packets. nat / mangle / raw / security chains with policy ACCEPT are
  // normal and must not be flagged for missing default-deny.
  // ── overbroad-source-trust ─────────────────────────────────────────
  // A source prefix this short is "any" wearing a costume: 0.0.0.0/1 is
  // half the internet, a public /8 is 16M addresses — yet none of them
  // match isSourceAny, so an admin port "restricted" to 128.0.0.0/2
  // sails past every any-source check (and past most human reviews,
  // which see "-s something" and move on). Private space is exempt: a
  // 10.0.0.0/8 or ULA trust is a normal site-wide rule. Flagged per
  // ACCEPT rule in filter tables only; the fix is to scope the CIDR to
  // the real network — or drop the pretence so the any-source smells
  // can see it for what it is.
  const OVERBROAD_V4_BITS = 8;   // /0../8 public v4 → flag
  const OVERBROAD_V6_BITS = 16;  // /0../16 public v6 → flag (2000::/3 = all global unicast)

  const PRIVATE_EXEMPT = ['10.0.0.0/8', '127.0.0.0/8', 'fc00::/7', 'fe80::/10', '::1/128'];

  // cidrSubsetOrAny already handles family mismatch and unparseable input
  // (both → false), so membership is a plain subset test per exempt net.
  function isPrivateExempt(src) {
    return PRIVATE_EXEMPT.some(net => cidrSubsetOrAny(src, net));
  }

  function detectOverbroadSource(chain, table, findings) {
    const rules = chain.rules || [];
    for (let i = 0; i < rules.length; i++) {
      const rule = rules[i];
      if (!isAcceptAction(rule)) continue;
      const src = rule.tokens && rule.tokens.source;
      if (!src || isAnyCidr(src)) continue;      // true "any" is the other smells' job
      const parsed = parseCidr(src);
      if (!parsed) continue;
      const threshold = parsed.family === 'v6' ? OVERBROAD_V6_BITS : OVERBROAD_V4_BITS;
      if (parsed.bits > threshold) continue;
      if (isPrivateExempt(src)) continue;
      findings.push({
        id: 'overbroad-source-trust',
        severity: 'warning',
        table: table.name,
        tableFamily: table.family || null,
        chain: chain.name,
        ruleIdx: i,
        title: `Accepts from ${src} — a /${parsed.bits} public range is "any" in costume`,
        details: `A source prefix this short${parsed.family === 'v4' && parsed.bits === 1 ? ' (half the internet)' : ''} evades every any-source check while restricting almost nothing. Scope it to the real network, or remove the source match so the any-source smells can judge the rule honestly. Rule: ${rule.raw || ''}`
      });
    }
  }

  // Source ranges that can never legitimately ORIGINATE inbound traffic:
  // "this network" (0/8), link-local (169.254/16 — never routed off the
  // wire), the TEST-NET / documentation blocks, reserved future-use space
  // (240/4), and the v6 documentation prefix. A packet ARRIVING with one of
  // these as its source is spoofed; an ACCEPT that trusts it is either
  // botched anti-spoofing or a copy-paste that trusts the untrustable.
  // Loopback (127/8, ::1) is deliberately NOT here — its own pair of smells
  // (loopback-not-allowed / missing-loopback-spoof-drop) owns that story.
  // CGNAT (100.64/10) and RFC1918 are legitimate behind many networks, so
  // they stay out to avoid crying wolf.
  const BOGON_NETS = [
    '0.0.0.0/8', '169.254.0.0/16', '192.0.2.0/24', '198.51.100.0/24',
    '203.0.113.0/24', '240.0.0.0/4', '2001:db8::/32',
  ];

  // A DROP/REJECT of a bogon source is correct anti-spoofing; only an ACCEPT
  // that trusts it is the problem — same "wide caution ok, wide trust not"
  // rule as overbroad-source-trust and mac-based-trust.
  function detectBogonSourceAccept(chain, table, findings) {
    const rules = chain.rules || [];
    for (let i = 0; i < rules.length; i++) {
      const rule = rules[i];
      if (!isAcceptAction(rule)) continue;
      const src = rule.tokens && rule.tokens.source;
      if (!src || isAnyCidr(src)) continue;
      const bogon = BOGON_NETS.find((net) => cidrSubsetOrAny(src, net));
      if (!bogon) continue;
      findings.push({
        id: 'bogon-source-accept',
        severity: 'warning',
        table: table.name,
        tableFamily: table.family || null,
        chain: chain.name,
        ruleIdx: i,
        title: `Accepts from ${src} — a bogon/non-routable source (${bogon})`,
        details: `Traffic arriving with a source in ${bogon} is spoofed: that range can't legitimately originate a packet reaching this host. Accepting it is either botched anti-spoofing or misplaced trust — drop these sources on external interfaces instead. Rule: ${rule.raw || ''}`
      });
    }
  }

  function isFilterTableName(name) {
    if (!name) return true; // some formats lack table names (ufw): treat as filter
    const n = String(name).toLowerCase();
    return n === 'filter';
  }

  function isDropPolicy(p)   { return typeof p === 'string' && /^drop$/i.test(p); }
  function isRejectPolicy(p) { return typeof p === 'string' && /^reject$/i.test(p); }

  function hasFinalCatchAllDrop(chain) {
    if (!Array.isArray(chain.rules) || chain.rules.length === 0) return false;
    const last = chain.rules[chain.rules.length - 1];
    if (!last) return false;
    const a = String(last.action || '').toUpperCase();
    if (a !== 'DROP' && a !== 'REJECT') return false;
    // catch-all = no match at all (any traffic)
    const t = last.tokens || {};
    const hasAnyMatch =
      t.source || t.destination || t.dport || t.sport || t.protocol ||
      t.iif || t.oif || t.in_interface || t.out_interface;
    return !hasAnyMatch;
  }

  function isAcceptAction(rule) {
    const a = String(rule.action || '').toUpperCase();
    return a === 'ACCEPT';
  }

  function isSourceAny(rule) {
    const s = rule.tokens && rule.tokens.source;
    if (!s) return true;
    const v = String(s).trim();
    return v === '0.0.0.0/0' || v === '::/0' || /^any(where)?$/i.test(v);
  }

  function hasNoPortRestriction(rule) {
    const t = rule.tokens || {};
    return !t.dport && !t.sport;
  }

  function isLoopbackRule(rule) {
    const t = rule.tokens || {};
    const iface = t.iif || t.in_interface || t.iifname || '';
    if (typeof iface === 'string' && /(^|")lo(\b|")/.test(iface)) return true;
    const raw = String(rule.raw || '');
    return /-i\s+lo\b/.test(raw) || /iifname\s+"lo"/.test(raw);
  }

  function isEstablishedRule(rule) {
    const raw = String(rule.raw || '');
    return /ctstate[\s=]+[A-Z,_]*(RELATED|ESTABLISHED)/i.test(raw) ||
           /ct\s+state\s+[a-z,_\s]*(established|related)/i.test(raw);
  }

  // ── missing-loopback-spoof-drop ────────────────────────────────────
  // The other half of "loopback traffic is configured" (CIS 3.4.2):
  // loopback-not-allowed demands the `-i lo ACCEPT`; this one demands its
  // companion — DROP anything claiming a 127.0.0.0/8 (or ::1) source that
  // arrives on a real interface. A spoofed loopback source rides a plain
  // `--dport 80 ACCEPT` just like a legitimate packet, and services that
  // trust "it came from localhost" believe it. The kernel normally drops
  // these as martians, but `route_localnet=1` re-opens the door — and
  // container tooling flips it (kube-proxy did, CVE-2020-8558), so the
  // firewall rule is the belt to the kernel's braces. Only raised when the
  // chain HAS the lo accept (the broken-loopback case is loopback-not-
  // allowed's job) and has an accept a spoofed packet could ride; a drop
  // placed AFTER those accepts is flagged too, pointing at the misplaced
  // rule. Skipped for ufw, whose before.rules never show in `ufw status`.
  function isLoopbackSpoofDrop(rule) {
    const a = String(rule.action || '').toUpperCase();
    if (a !== 'DROP' && a !== 'REJECT') return false;
    const src = String((rule.tokens && rule.tokens.source) || '').replace(/"/g, '');
    if (/^127\./.test(src)) return true; // 127.0.0.0/8 or narrower
    return src === '::1' || src === '::1/128';
  }

  function flagMissingLoopbackSpoofDrop(chain, table, findings, format) {
    if (format === 'ufw') return;
    const hasDenyPosture =
      isDropPolicy(chain.policy) ||
      isRejectPolicy(chain.policy) ||
      hasFinalCatchAllDrop(chain);
    if (!hasDenyPosture) return;
    const rules = chain.rules || [];
    if (!rules.some(r => isAcceptAction(r) && isLoopbackRule(r))) return;
    const firstRideableAccept = rules.findIndex(r =>
      isAcceptAction(r) && !isLoopbackRule(r) && !isEstablishedRule(r));
    if (firstRideableAccept === -1) return;
    const dropIdx = rules.findIndex(isLoopbackSpoofDrop);
    if (dropIdx !== -1 && dropIdx < firstRideableAccept) return;
    const misplaced = dropIdx !== -1;
    findings.push({
      id: 'missing-loopback-spoof-drop',
      severity: 'info',
      table: table.name,
      tableFamily: table.family || null,
      chain: chain.name,
      ruleIdx: misplaced ? dropIdx : null,
      title: misplaced
        ? `${chain.name} drops spoofed loopback traffic only after its ACCEPT rules`
        : `${chain.name} accepts loopback but never drops spoofed loopback sources`,
      details: misplaced
        ? 'The loopback-source drop sits below ACCEPT rules, so a packet claiming a 127.0.0.0/8 (or ::1) source rides any open port before the drop is consulted. Move it up, right after the `-i lo ACCEPT`.'
        : 'Pair the `-i lo ACCEPT` with `-s 127.0.0.0/8 -j DROP` (ip6tables: `-s ::1 -j DROP`; nft: `ip saddr 127.0.0.0/8 drop`) right below it. The kernel normally drops these as martians, but `route_localnet=1` — flipped by container tooling (kube-proxy, CVE-2020-8558) — re-opens the door, and services that trust "it came from localhost" will believe a spoofed source.'
    });
  }

  // Total number of ports a rule's dport expression opens (0 if it has no
  // dport, i.e. no port restriction — that's permissive-accept's job).
  function dportSpan(rule) {
    const d = rule.tokens && rule.tokens.dport;
    if (!d) return 0;
    const iv = portIntervals(String(d));
    if (!iv) return 0;
    let n = 0;
    for (const [lo, hi] of iv) n += (hi - lo + 1);
    return n;
  }

  function matchAdminPort(rule) {
    const d = rule.tokens && rule.tokens.dport;
    if (!d) return null;
    for (const portStr of Object.keys(ADMIN_PORTS)) {
      const port = +portStr;
      if (portInDport(port, String(d))) {
        return { port, service: ADMIN_PORTS[portStr] };
      }
    }
    return null;
  }

  // Determines whether a numeric port is matched by an iptables / nft / ufw
  // dport expression. Supports single value ("22"), comma list ("22,80"), nft
  // set ("{ 22, 80, 443 }") and iptables range ("1024:65535").
  function portInDport(port, dport) {
    const v = dport.trim();
    if (v === String(port)) return true;
    const setM = v.match(/^\{([^}]+)\}$/);
    const inner = setM ? setM[1] : v;
    if (inner.includes(',')) {
      return inner.split(',').map(s => s.trim()).includes(String(port));
    }
    const range = inner.match(/^(\d+)[:-](\d+)$/);
    if (range) {
      return port >= +range[1] && port <= +range[2];
    }
    return false;
  }

  function zeroCounts() {
    return { error: 0, warning: 0, info: 0, total: 0 };
  }

  // Builds a counts breakdown and an index keyed by "table::chain::ruleIdx"
  // (or "table::chain::*" for chain-level findings) so renderers can attach a
  // pill to the right row without scanning the array.
  function summarize(findings) {
    const counts = zeroCounts();
    const byKey = {};
    for (const f of findings) {
      counts[f.severity] = (counts[f.severity] || 0) + 1;
      counts.total++;
      const key = `${f.table}::${f.chain}::${f.ruleIdx == null ? '*' : f.ruleIdx}`;
      (byKey[key] = byKey[key] || []).push(f);
    }
    return { findings, counts, byKey };
  }

  // ── duplicate-rule ───────────────────────────────────────────────────
  // The same rule appearing twice in a chain is the signature of a
  // non-idempotent provisioning script — an `iptables -A …` in rc.local or
  // a deploy hook that appends on every boot / release. A duplicated
  // terminal rule at least never fires, but a duplicated side-effect rule
  // runs twice: a LOG writes two lines per packet, a jump traverses its
  // subchain again, a second MASQUERADE is dead weight hiding drift.
  // Exact textual copies are this smell's domain — detectShadowedRules
  // skips them so each duplicate is reported once, with the right cause.
  // Skipped for ufw: its CLI refuses to add an already-existing rule.
  function normalizedRaw(rule) {
    return String(rule.raw || '').trim().replace(/\s+/g, ' ');
  }

  function detectDuplicateRules(chain, table, findings, format) {
    if (format === 'ufw') return;
    const rules = chain.rules || [];
    const firstSeen = new Map();
    for (let i = 0; i < rules.length; i++) {
      const key = normalizedRaw(rules[i]);
      if (!key) continue;
      if (!firstSeen.has(key)) {
        firstSeen.set(key, i);
        continue;
      }
      const orig = firstSeen.get(key);
      findings.push({
        id: 'duplicate-rule',
        severity: 'warning',
        table: table.name,
        tableFamily: table.family || null,
        chain: chain.name,
        ruleIdx: i,
        title: `Duplicate rule — identical to rule #${orig + 1}`,
        details: `${rules[i].raw || ''} — byte-for-byte copy of rule #${orig + 1}, usually left behind by a provisioning script that appends instead of checking (\`iptables -A\` on every boot). A duplicated LOG logs every packet twice and a duplicated jump traverses its chain again; a duplicated terminal rule never fires. Either way the copy hides drift — delete it and make the script idempotent (\`iptables -C … || iptables -A …\`).`,
        duplicateOf: orig
      });
    }
  }

  // ── shadow detection ─────────────────────────────────────────────────
  // For each terminal rule N, check whether any earlier terminal rule M in
  // the same chain already captures every packet that N matches. Strict
  // subset semantics on protocol / source / destination / dport / sport;
  // jumps are not considered terminal (they could RETURN); rules with
  // divergent ct-state markers are not comparable. Byte-identical copies
  // are excluded — those are duplicate-rule findings, not shadowing.

  function detectShadowedRules(chain, table, findings, format) {
    const rules = chain.rules || [];
    for (let j = 1; j < rules.length; j++) {
      const N = rules[j];
      if (!isTerminalAction(N)) continue;
      for (let i = 0; i < j; i++) {
        const M = rules[i];
        if (!isTerminalAction(M)) continue;
        if (normalizedRaw(M) === normalizedRaw(N)) continue; // duplicate-rule's domain
        if (!sameCtStateContext(M, N)) continue;
        if (!sameFamily(M, N, table, format)) continue;
        if (!isPacketSpaceSubset(N, M)) continue;

        const aM = String(M.action || '').toUpperCase();
        const aN = String(N.action || '').toUpperCase();
        const sameAction = aM === aN;
        findings.push({
          id: 'shadowed-rule',
          severity: 'warning',
          table: table.name,
          tableFamily: table.family || null,
          chain: chain.name,
          ruleIdx: j,
          title: sameAction
            ? `Rule never fires — redundant after rule #${i + 1} which already accepts/drops this traffic`
            : `Rule never fires — earlier rule #${i + 1} (${aM}) intercepts this traffic before it reaches a ${aN}`,
          details: (N.raw || '') + ` — shadowed by: ${M.raw || ('rule #' + (i + 1))}`,
          shadowedBy: i
        });
        break; // first (oldest) shadower wins
      }
    }
  }

  function isTerminalAction(rule) {
    const a = String(rule.action || '').toUpperCase();
    return a === 'ACCEPT' || a === 'DROP' || a === 'REJECT' || a === 'RETURN';
  }

  // Two rules are only comparable for shadow purposes if they share the same
  // ct-state context. "Same" means both unset, or both set to the exact same
  // (order-independent) state list.
  function sameCtStateContext(m, n) {
    return ctState(m) === ctState(n);
  }
  function ctState(rule) {
    const raw = String(rule.raw || '');
    const m1 = raw.match(/-m\s+conntrack\s+--ctstate\s+([A-Z,_]+)/i) || raw.match(/--ctstate\s+([A-Z,_]+)/i);
    if (m1) return m1[1].toUpperCase().split(',').sort().join(',');
    const m2 = raw.match(/\bct\s+state\s+([A-Za-z,_\s]+?)(?:\s+(accept|drop|reject|return|jump|goto|log|counter|$)|$)/);
    if (m2) return m2[1].toLowerCase().replace(/\s+/g, '').split(',').filter(Boolean).sort().join(',');
    return '';
  }

  function isPacketSpaceSubset(n, m) {
    // The subset check only models 5 dimensions (protocol, src, dst, dport,
    // sport). Any rule that uses a match we don't model — interface (-i/-o),
    // rate limit, recent, mac, mark, etc. — is treated as not comparable so
    // we don't claim "subset" when an unseen constraint might actually rule
    // it out.
    if (hasUnmodeledMatch(n) || hasUnmodeledMatch(m)) return false;

    const tN = n.tokens || {};
    const tM = m.tokens || {};

    // Protocol: if M doesn't constrain it, N is free. If M does, N must agree.
    const protoM = normalizeProto(tM.protocol || extractProtoFromRaw(m.raw));
    const protoN = normalizeProto(tN.protocol || extractProtoFromRaw(n.raw));
    if (protoM && protoM !== protoN) return false;

    if (!cidrSubsetOrAny(tN.source, tM.source)) return false;
    if (!cidrSubsetOrAny(tN.destination, tM.destination)) return false;
    if (!portSubsetOrAny(tN.dport, tM.dport)) return false;
    if (!portSubsetOrAny(tN.sport, tM.sport)) return false;
    return true;
  }

  function hasUnmodeledMatch(rule) {
    const raw = String(rule.raw || '');
    // Interface restrictions
    if (/(?:^|\s)-i\s+\S/.test(raw)) return true;
    if (/(?:^|\s)-o\s+\S/.test(raw)) return true;
    if (/\b(?:iifname|oifname|iif|oif)\s+/.test(raw)) return true;
    // Layer-7 / rate / per-host counters
    if (/-m\s+(?:limit|recent|hashlimit|connlimit|owner|mark|mac|string|hexstring|set|policy|conntrack(?!\s+--ctstate))/.test(raw)) return true;
    if (/\b(?:limit\s+rate|meter\s)/.test(raw)) return true;
    return false;
  }

  function normalizeProto(p) {
    if (!p) return null;
    const s = String(p).toLowerCase().trim();
    if (s === 'all' || s === '*') return null;
    return s;
  }
  function extractProtoFromRaw(raw) {
    const s = String(raw || '');
    let m;
    if ((m = s.match(/(?:^|\s)-p\s+(\S+)/)))                return m[1].toLowerCase(); // iptables: -p tcp
    if ((m = s.match(/\bmeta\s+l4proto\s+(\S+)/)))          return m[1].toLowerCase(); // nft: meta l4proto tcp
    if ((m = s.match(/\bip6\s+nexthdr\s+(\S+)/)))           return m[1].toLowerCase(); // nft v6: ip6 nexthdr icmpv6
    if ((m = s.match(/\bip\s+protocol\s+(\S+)/)))           return m[1].toLowerCase(); // nft v4: ip protocol icmp
    return null;
  }

  // Same family (v4 vs v6) is required for two rules to shadow each other.
  // For iptables/ip6tables the format itself fixes the family. For ufw, IPv6
  // rules are tagged with "(v6)" in the To column. For nft, the address
  // family is on the table (ip, ip6, inet, …).
  function sameFamily(m, n, table, format) {
    const fM = ruleFamily(m, table, format);
    const fN = ruleFamily(n, table, format);
    if (fM === 'any' || fN === 'any') return true;
    return fM === fN;
  }
  function ruleFamily(rule, table, format) {
    if (format === 'iptables')   return 'v4';
    if (format === 'ip6tables')  return 'v6';
    if (format === 'ufw') {
      return /\(v6\)/i.test(String(rule.raw || '')) ? 'v6' : 'v4';
    }
    if (format === 'nftables') {
      const fam = String((table && table.family) || '').toLowerCase();
      if (fam === 'ip6') return 'v6';
      if (fam === 'ip')  return 'v4';
      // 'inet' / 'bridge' / 'netdev' / 'arp' carry mixed traffic; inspect rule
      // syntax for the family-specific keywords.
      const raw = String(rule.raw || '');
      if (/\bip6\s+/.test(raw))  return 'v6';
      if (/\bip\s+(?:saddr|daddr|protocol)\b/.test(raw)) return 'v4';
      return 'any';
    }
    return 'any';
  }

  // CIDR subset: is `nSrc` ⊆ `mSrc`? "any" on either side means any.
  function cidrSubsetOrAny(nSrc, mSrc) {
    if (!mSrc || isAnyCidr(mSrc)) return true;          // M unconstrained → anything fits
    if (!nSrc || isAnyCidr(nSrc)) return false;         // M restricts, N doesn't → N is wider
    const nP = parseCidr(nSrc);
    const mP = parseCidr(mSrc);
    if (!nP || !mP) return false;                       // unparseable → be safe
    if (nP.family !== mP.family) return false;
    if (nP.bits < mP.bits) return false;                // n's prefix is shorter → wider
    // N ⊆ M iff they agree on M's prefix bits. Same arithmetic for v4 (32-bit)
    // and v6 (128-bit) now that both carry a BigInt value.
    const totalBits = nP.family === 'v6' ? 128n : 32n;
    const shift = totalBits - BigInt(mP.bits);
    return (nP.value >> shift) === (mP.value >> shift);
  }
  function isAnyCidr(s) {
    const v = String(s || '').trim();
    return v === '' || v === '0.0.0.0/0' || v === '::/0' || /^any(where)?$/i.test(v);
  }
  // Parse an IPv6 address to a 128-bit BigInt, or null if malformed. Handles
  // "::" zero-compression, an optional %zone suffix, and an IPv4-mapped tail
  // (::ffff:1.2.3.4). Returns null on anything it can't represent exactly, so
  // the subset check stays conservative.
  function parseIpv6ToBigInt(addr) {
    let s = String(addr).trim();
    const pct = s.indexOf('%');
    if (pct !== -1) s = s.slice(0, pct);        // drop scope id (fe80::1%eth0)

    // IPv4-mapped suffix → two hex groups.
    const v4m = s.match(/^(.*:)((?:\d{1,3}\.){3}\d{1,3})$/);
    if (v4m) {
      const o = v4m[2].split('.').map(Number);
      if (o.some((x) => x > 255)) return null;
      s = v4m[1] + ((o[0] << 8) | o[1]).toString(16) + ':' + ((o[2] << 8) | o[3]).toString(16);
    }

    const halves = s.split('::');
    if (halves.length > 2) return null;         // more than one "::" is illegal
    const head = halves[0] === '' ? [] : halves[0].split(':');
    let groups;
    if (halves.length === 1) {
      if (head.length !== 8) return null;        // no "::" → must be all 8 groups
      groups = head;
    } else {
      const tail = halves[1] === '' ? [] : halves[1].split(':');
      const missing = 8 - (head.length + tail.length);
      if (missing < 1) return null;              // "::" must stand for ≥1 group
      groups = [...head, ...Array(missing).fill('0'), ...tail];
    }
    let value = 0n;
    for (const g of groups) {
      if (!/^[0-9a-f]{1,4}$/i.test(g)) return null;
      value = (value << 16n) | BigInt(parseInt(g, 16));
    }
    return value & ((1n << 128n) - 1n);
  }

  function parseCidr(s) {
    const str = String(s).trim();
    if (str.includes(':')) {
      const m = str.match(/^([0-9a-f:.%]+)(?:\/(\d+))?$/i);
      if (!m) return null;
      const value = parseIpv6ToBigInt(m[1]);
      if (value === null) return null;
      const bits = m[2] !== undefined ? +m[2] : 128;
      if (bits < 0 || bits > 128) return null;
      return { family: 'v6', value, bits };
    }
    const m = str.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)(?:\/(\d+))?$/);
    if (!m) return null;
    const value =
      (BigInt(+m[1]) << 24n) |
      (BigInt(+m[2]) << 16n) |
      (BigInt(+m[3]) <<  8n) |
       BigInt(+m[4]);
    const bits = m[5] !== undefined ? +m[5] : 32;
    return { family: 'v4', value: value & 0xFFFFFFFFn, bits };
  }

  // Port subset using interval lists. A port expression is converted to a
  // list of [lo, hi] inclusive intervals; subset is established when every
  // interval on the left fits inside some interval on the right.
  function portSubsetOrAny(nPort, mPort) {
    if (!mPort) return true;
    if (!nPort) return false;
    const nIv = portIntervals(nPort);
    const mIv = portIntervals(mPort);
    if (!nIv || !mIv) return false;
    for (const [aL, aH] of nIv) {
      let covered = false;
      for (const [bL, bH] of mIv) {
        if (aL >= bL && aH <= bH) { covered = true; break; }
      }
      if (!covered) return false;
    }
    return true;
  }
  function portIntervals(p) {
    const str = String(p).trim();
    const setM = str.match(/^\{([^}]+)\}$/);
    const inner = setM ? setM[1] : str;
    const parts = inner.includes(',') ? inner.split(',').map(s => s.trim()) : [inner];
    const out = [];
    for (const part of parts) {
      const r = part.match(/^(\d+)[:-](\d+)$/);
      if (r) {
        out.push([+r[1], +r[2]]);
      } else if (/^\d+$/.test(part)) {
        const v = +part;
        out.push([v, v]);
      } else {
        return null;
      }
    }
    return out;
  }

  // Probes the chain with a battery of representative inbound packets (one
  // per admin port) by replaying them through the trace engine. Each probe
  // whose verdict comes from chain policy ACCEPT — i.e. nothing matched it
  // explicitly — contributes to a single finding for this chain. The probe
  // packet attached to the finding is the first one that fell through, so
  // clicking it reproduces a concrete failure in the Trace tab.
  function detectFallthroughAccept(result, chain, table, format, findings) {
    if (!window.FirewallScope || typeof window.FirewallScope.trace !== 'function') return;
    if (!isV4ProbeApplicable(table, format)) return;
    const direction = inboundDirection(chain, format);
    if (!direction) return;

    const fallenServices = [];
    let firstFallenProbe = null;

    for (const portStr of Object.keys(ADMIN_PORTS)) {
      const port = +portStr;
      const probe = {
        direction,
        protocol: 'tcp',
        source: '1.2.3.4',
        destination: '10.0.0.1',
        dport: port,
        state: 'NEW'
      };
      const report = window.FirewallScope.trace(result, probe);
      if (!report || report.error) continue;
      if (report.verdict !== 'ACCEPT') continue;
      if (!report.finalRule || report.finalRule.ruleIdx != null) continue;
      if (report.finalRule.chain !== chain.name) continue;

      fallenServices.push(`${ADMIN_PORTS[portStr]} (${port})`);
      if (!firstFallenProbe) firstFallenProbe = probe;
    }

    if (!firstFallenProbe) return;

    const listed = fallenServices.join(', ');
    const title = fallenServices.length === 1
      ? `${chain.name} lets a probe for ${listed} fall through to policy ACCEPT`
      : `${chain.name} lets probes for ${listed} fall through to policy ACCEPT`;
    const details =
      `Representative inbound probes landed on the chain's default policy with no rule matching. ` +
      `Click to inspect the trace for ${fallenServices[0]}.`;

    findings.push({
      id: 'fallthrough-accept',
      severity: 'warning',
      table: table.name,
      tableFamily: table.family || null,
      chain: chain.name,
      ruleIdx: null,
      title,
      details,
      probePacket: firstFallenProbe
    });
  }

  // The probe synthesises an IPv4 packet. ip6tables rulesets and nft `ip6`
  // family tables wouldn't be probed faithfully (the trace's v6 arithmetic
  // is limited and many rules would be silently skipped), so we exclude
  // them to avoid false positives. nft `inet` and `ip` are kept — they are
  // either v4 or dual-stack and the worst-case is a missed v6-only ACCEPT,
  // which the user can spot in the trace anyway.
  function isV4ProbeApplicable(table, format) {
    if (format === 'ip6tables') return false;
    if (format === 'nftables') {
      const fam = String(table.family || '').toLowerCase();
      if (fam === 'ip6') return false;
    }
    return true;
  }

  function inboundDirection(chain, format) {
    if (format === 'nftables') {
      if (!chain.builtIn) return null;
      if (chain.hook === 'input')   return 'input';
      if (chain.hook === 'forward') return 'forward';
      return null;
    }
    if (chain.name === 'INPUT')   return 'input';
    if (chain.name === 'FORWARD') return 'forward';
    return null;
  }

  // Any rule placed after a catch-all DROP / REJECT is unreachable: the
  // catch-all sweeps every packet first. We surface one finding per dead
  // rule so the Lint tab can pinpoint each line. Overlaps intentionally
  // with `shadowed-rule` on terminal actions (each angle is descriptive
  // on its own; jumps / LOG / counter rules after the catch-all are only
  // caught here because shadowed-rule excludes non-terminals).
  function detectRuleAfterPolicyDrop(chain, table, findings) {
    const rules = chain.rules || [];
    let catchAllIdx = -1;
    for (let i = 0; i < rules.length; i++) {
      if (isCatchAllDeny(rules[i])) { catchAllIdx = i; break; }
    }
    if (catchAllIdx === -1 || catchAllIdx >= rules.length - 1) return;
    const catchAll = rules[catchAllIdx];
    const catchAllAction = String(catchAll.action || '').toUpperCase();
    for (let j = catchAllIdx + 1; j < rules.length; j++) {
      findings.push({
        id: 'rule-after-policy-drop',
        severity: 'warning',
        table: table.name,
        tableFamily: table.family || null,
        chain: chain.name,
        ruleIdx: j,
        title: `Dead rule — unreachable after catch-all ${catchAllAction} at rule #${catchAllIdx + 1}`,
        details: rules[j].raw || ''
      });
    }
  }

  function isCatchAllDeny(rule) {
    const a = String(rule.action || '').toUpperCase();
    if (a !== 'DROP' && a !== 'REJECT') return false;
    const t = rule.tokens || {};
    if (t.source || t.destination || t.dport || t.sport || t.protocol) return false;
    if (t.iif || t.oif || t.in_interface || t.out_interface) return false;
    if (ctState(rule)) return false;
    if (hasUnmodeledMatch(rule)) return false;
    return true;
  }

  // INPUT chains with a deny posture (policy DROP/REJECT, or a final
  // catch-all DROP) that omit an explicit `-i lo -j ACCEPT` rule will
  // block loopback traffic — a classic source of broken local services
  // (Postgres on 127.0.0.1, systemd-resolved, X11 sockets, etc.).
  function flagLoopbackNotAllowed(chain, table, findings) {
    const hasDenyPosture =
      isDropPolicy(chain.policy) ||
      isRejectPolicy(chain.policy) ||
      hasFinalCatchAllDrop(chain);
    if (!hasDenyPosture) return;
    const allowsLoopback = (chain.rules || []).some(r => isAcceptAction(r) && isLoopbackRule(r));
    if (allowsLoopback) return;
    findings.push({
      id: 'loopback-not-allowed',
      severity: 'warning',
      table: table.name,
      tableFamily: table.family || null,
      chain: chain.name,
      ruleIdx: null,
      title: `${chain.name} has default-deny but does not explicitly allow loopback`,
      details: 'No `-i lo -j ACCEPT` (or nft `iifname "lo" accept`) rule found. Local services that bind to 127.0.0.1 will be blocked.'
    });
  }

  // ── drop-without-log ───────────────────────────────────────────────
  // A deny posture that never logs leaves no forensic trail: dropped
  // probes (port scans, brute-force attempts) simply vanish. Info rather
  // than warning — the ruleset is not less safe, just blind. Skipped for
  // ufw, whose backend inserts its own rate-limited LOG rules and reports
  // them only through `ufw status verbose`'s "Logging:" line.
  function flagDropWithoutLog(chain, table, findings, format) {
    if (format === 'ufw') return;
    const hasDenyPosture =
      isDropPolicy(chain.policy) ||
      isRejectPolicy(chain.policy) ||
      hasFinalCatchAllDrop(chain);
    if (!hasDenyPosture) return;
    if ((chain.rules || []).some(isLogRule)) return;
    findings.push({
      id: 'drop-without-log',
      severity: 'info',
      table: table.name,
      tableFamily: table.family || null,
      chain: chain.name,
      ruleIdx: null,
      title: `${chain.name} drops traffic without logging any of it`,
      details: 'No LOG / NFLOG (or nft `log`) rule found before the default-deny. Dropped packets — port scans, brute-force attempts — leave no trace for later forensics. Consider a rate-limited log rule, e.g. `-m limit --limit 5/min -j LOG --log-prefix "DROP-INPUT: "` (nft: `limit rate 5/minute log prefix "DROP-INPUT: "`).'
    });
  }

  function isLogRule(rule) {
    const a = String(rule.action || '').toUpperCase();
    if (a === 'LOG' || a === 'NFLOG') return true;
    // nft: `log` is a statement inside the rule, not its verdict — the parser
    // reports the verdict (drop/accept/…) as the action, so check the raw
    // text. The leading \s keeps iptables' own `--log-prefix` from matching.
    return /(^|\s)log(\s|$)/.test(String(rule.raw || ''));
  }

  // ── missing-invalid-drop ───────────────────────────────────────────
  // Standard hardening drops conntrack INVALID before any accept: a bare
  // `--dport 80 -j ACCEPT` matches malformed / out-of-window TCP just as
  // happily as a legitimate SYN, so crafted packets ride every open port.
  // The default-deny only catches traffic that matches NO accept — this
  // gap is about traffic that does. Only worth raising when the chain
  // actually accepts something a crafted packet could ride (a non-loopback,
  // non-conntrack accept); an INVALID drop placed AFTER those accepts is
  // flagged too, pointing at the misplaced rule. Info severity, like
  // drop-without-log: a hardening gap, not an open door. Skipped for ufw,
  // whose backend drops INVALID in ufw-before-input without showing it.
  function flagMissingInvalidDrop(chain, table, findings, format) {
    if (format === 'ufw') return;
    const hasDenyPosture =
      isDropPolicy(chain.policy) ||
      isRejectPolicy(chain.policy) ||
      hasFinalCatchAllDrop(chain);
    if (!hasDenyPosture) return;
    const rules = chain.rules || [];
    const firstRideableAccept = rules.findIndex(r =>
      isAcceptAction(r) && !isLoopbackRule(r) && !isEstablishedRule(r));
    if (firstRideableAccept === -1) return;
    const invalidIdx = rules.findIndex(isInvalidDropRule);
    if (invalidIdx !== -1 && invalidIdx < firstRideableAccept) return;
    const misplaced = invalidIdx !== -1;
    findings.push({
      id: 'missing-invalid-drop',
      severity: 'info',
      table: table.name,
      tableFamily: table.family || null,
      chain: chain.name,
      ruleIdx: misplaced ? invalidIdx : null,
      title: misplaced
        ? `${chain.name} drops INVALID packets only after its ACCEPT rules`
        : `${chain.name} never drops INVALID packets`,
      details: misplaced
        ? 'The `ctstate INVALID` drop sits below ACCEPT rules, so malformed / out-of-window packets aimed at an open port are accepted before it is ever consulted. Move it above the first ACCEPT.'
        : 'No `-m conntrack --ctstate INVALID -j DROP` (nft: `ct state invalid drop`) rule found before the port accepts. Malformed / out-of-window packets match a plain `--dport` ACCEPT just like legitimate traffic — drop INVALID early, right after the loopback rule.'
    });
  }

  function isInvalidDropRule(rule) {
    const a = String(rule.action || '').toUpperCase();
    if (a !== 'DROP' && a !== 'REJECT') return false;
    const raw = String(rule.raw || '');
    return /ctstate[\s=]+[A-Z,_]*INVALID/i.test(raw) ||
           /ct\s+state\s+[a-z,_\s]*invalid/.test(raw);
  }

  // ── unlimited-log ──────────────────────────────────────────────────
  // A LOG rule with no rate limit turns logging into an attack surface:
  // every matching packet writes a syslog line, so a port scan or a plain
  // packet flood becomes a disk-filling (and log-drowning) primitive. The
  // fix is one match away: `-m limit --limit 5/min` / nft `limit rate`.
  // Skipped for ufw — its LOG rules live in the backend and never show in
  // `ufw status`, so there is nothing to judge.
  function isRateLimited(rule) {
    const raw = String(rule.raw || '');
    return /-m\s+(limit|hashlimit)\b/.test(raw) || /\blimit\s+rate\b/.test(raw);
  }

  function detectUnlimitedLog(chain, table, findings, format) {
    if (format === 'ufw') return;
    const rules = chain.rules || [];
    for (let i = 0; i < rules.length; i++) {
      const rule = rules[i];
      if (!isLogRule(rule)) continue;
      if (isRateLimited(rule)) continue;
      findings.push({
        id: 'unlimited-log',
        severity: 'warning',
        table: table.name,
        tableFamily: table.family || null,
        chain: chain.name,
        ruleIdx: i,
        title: 'LOG rule has no rate limit',
        details: 'Every matching packet writes a log line — a port scan or packet flood becomes a disk-filling attack. Add `-m limit --limit 5/min` (nft: `limit rate 5/minute`) in front of the log action.'
      });
    }
  }

  // ── log-tcp-sequence ───────────────────────────────────────────────
  // The LOG target has one flag with a documented security cost:
  // `--log-tcp-sequence` writes each packet's TCP sequence numbers into
  // syslog, and the iptables man page is blunt about it — "This is a
  // security risk if the log is readable by users". Sequence numbers are
  // the raw material for off-path injection / connection hijacking, and
  // log lines routinely travel further than root (adm-group readable
  // /var/log, log shippers, centralised collectors). nft records the
  // same detail via `log flags tcp sequence` — and via the `log flags
  // all` shorthand, which people reach for as "verbose". The LOG trio,
  // completed: drop-without-log asks that a deny-posture chain log at
  // all, unlimited-log asks that logging be bounded, this one asks that
  // it not leak. Skipped for ufw — its CLI cannot express LOG flags.
  function logsTcpSequence(rule) {
    const raw = String(rule.raw || '');
    if (/--log-tcp-sequence\b/.test(raw)) return true;
    if (/\blog\s+flags\s+all\b/.test(raw)) return true;
    return /\blog\s+flags\s+tcp\s+[a-z,]*\bsequence\b/.test(raw);
  }

  function detectLogTcpSequence(chain, table, findings, format) {
    if (format === 'ufw') return;
    const rules = chain.rules || [];
    for (let i = 0; i < rules.length; i++) {
      const rule = rules[i];
      if (!isLogRule(rule)) continue;
      if (!logsTcpSequence(rule)) continue;
      findings.push({
        id: 'log-tcp-sequence',
        severity: 'warning',
        table: table.name,
        tableFamily: table.family || null,
        chain: chain.name,
        ruleIdx: i,
        title: 'LOG rule records TCP sequence numbers',
        details: '`--log-tcp-sequence` (nft: `log flags tcp sequence`, included in `log flags all`) writes TCP sequence numbers to syslog — the iptables man page calls it "a security risk if the log is readable by users". Sequence numbers are the raw material for connection injection / hijacking, and logs routinely reach log shippers and readers beyond root. Drop the flag — source, destination and ports are logged either way.'
      });
    }
  }

  // ── unlimited-icmp-echo ────────────────────────────────────────────
  // Answering ping from anywhere with no rate limit hands out a free
  // packet-reflection primitive: every echo-request costs the host an
  // echo-reply, so a spoofed-source flood turns it into an amplifier and
  // a direct one burns its CPU/bandwidth for free. The fix is the same
  // one unlimited-log teaches: `-m limit --limit 10/sec` / nft `limit
  // rate`. For IPv4 a blanket `-p icmp -j ACCEPT` counts (echo-request
  // is included); an explicit non-echo --icmp-type does not answer ping
  // and is skipped. For IPv6 only an EXPLICIT echo-request (type 128)
  // match counts — blanket ICMPv6 accepts are required hygiene (Neighbor
  // Discovery, PMTUD; icmpv6-blocked exists to demand them) and must not
  // be punished here. Skipped for ufw, whose ICMP handling lives in
  // before.rules and never shows in `ufw status`.
  function acceptsIcmpEcho(rule) {
    const text = `${rule.raw || ''} ${rule.match || ''}`;
    if (isIcmpv6Rule(rule)) {
      return /--icmpv6-type[\s=]+(echo-request|128)(\/|\s|$)/.test(text) ||
             /(^|\s)icmpv6\s+type\s+(echo-request|128)(\s|$)/.test(text);
    }
    const proto = String((rule.tokens && rule.tokens.protocol) || '').toLowerCase();
    // nft spellings never land in tokens.protocol: `ip protocol icmp`,
    // `meta l4proto icmp`, `icmp type echo-request`. The (^|\s)…(\s|$)
    // guards keep `icmpv6` / `ipv6-icmp` / `icmp6` from matching.
    if (proto !== 'icmp' && !/(^|\s)icmp(\s|$)/.test(text)) return false;
    const typed = text.match(/--icmp-type[\s=]+(\S+)/) ||
                  text.match(/(^|\s)icmp\s+type\s+(\S+)/);
    if (!typed) return true; // no type match = all types, echo included
    const type = typed[typed.length - 1];
    return /^(echo-request|8)(\/|$)/.test(type);
  }

  function detectUnlimitedIcmpEcho(chain, table, findings, format) {
    if (format === 'ufw') return;
    const rules = chain.rules || [];
    for (let i = 0; i < rules.length; i++) {
      const rule = rules[i];
      if (!isAcceptAction(rule)) continue;
      if (!isSourceAny(rule)) continue;
      if (!acceptsIcmpEcho(rule)) continue;
      if (isRateLimited(rule)) continue;
      findings.push({
        id: 'unlimited-icmp-echo',
        severity: 'info',
        table: table.name,
        tableFamily: table.family || null,
        chain: chain.name,
        ruleIdx: i,
        title: 'Answers ping from anywhere with no rate limit',
        details: 'An unthrottled echo-request ACCEPT makes the host a free reflector: every ping costs it a reply, so a spoofed-source flood uses it as an amplifier. Add `-m limit --limit 10/sec` (nft: `limit rate 10/second`) to the rule — legitimate diagnostics never need more.'
      });
    }
  }

  // ── admin-port-no-rate-limit ───────────────────────────────────────
  // An ACCEPT to an admin port (SSH, RDP, database consoles…) with no
  // per-source rate limit lets brute-force login attempts arrive at full
  // speed — a botnet can try thousands of passwords a second against sshd.
  // A netfilter throttle caps new connections per source *before* they
  // reach the service, and complements Fail2Ban (which reacts after the
  // fact, from the log). Recognises the connection-limiting matches
  // (`-m recent`, `-m hashlimit`, `-m connlimit`, plain `-m limit`) and the
  // nft spellings (`limit rate`, `ct count`). Info severity: defense in
  // depth, not an open door — and it composes with exposed-admin-port
  // (that one is about *who* can reach the port; this one about *how fast*
  // they can hammer it), so an unthrottled any-source SSH draws both.
  function hasBruteForceLimit(rule) {
    const raw = String(rule.raw || '');
    return /-m\s+(limit|hashlimit|connlimit|recent)\b/.test(raw) ||
           /\blimit\s+rate\b/.test(raw) ||
           /\bct\s+count\b/.test(raw);
  }

  function detectAdminPortNoRateLimit(chain, table, findings, format) {
    if (format === 'ufw') return; // ufw's own `limit` verb lives in the backend view
    const rules = chain.rules || [];
    for (let i = 0; i < rules.length; i++) {
      const rule = rules[i];
      if (!isAcceptAction(rule)) continue;
      const admin = matchAdminPort(rule);
      if (!admin) continue;
      if (hasBruteForceLimit(rule)) continue;
      findings.push({
        id: 'admin-port-no-rate-limit',
        severity: 'info',
        table: table.name,
        tableFamily: table.family || null,
        chain: chain.name,
        ruleIdx: i,
        title: `${admin.service} accepts new connections with no rate limit`,
        details: `An ACCEPT for ${admin.service} (port ${admin.port}) has no per-source throttle, so brute-force attempts hit it at full speed. Add a netfilter limit — \`-m recent\` / \`-m hashlimit\` / \`-m connlimit\` (nft: \`limit rate\` / \`ct count\`) — to cap attempts per source before they reach the service, and pair it with Fail2Ban. Independent of who can reach the port: even a source-restricted admin port is worth throttling.`
      });
    }
  }

  // ── mac-based-trust ────────────────────────────────────────────────
  // A MAC address is identification, not authentication: it is broadcast
  // to the whole local segment (ARP/NDP) and forged with one `ip link set
  // address` — so an ACCEPT keyed on the sender's MAC hands every LAN
  // neighbor a skeleton key. It also never survives routing (L2 only),
  // which makes the rule look scoped while restricting nothing an attacker
  // on the segment can't copy. Blocking by MAC stays unflagged — broad
  // caution is fine, borrowed trust is the smell (the same philosophy as
  // overbroad-source-trust and the DROP/REJECT exemption there).
  function detectMacBasedTrust(chain, table, findings, format) {
    if (format === 'ufw') return; // ufw's rule syntax has no MAC match
    const rules = chain.rules || [];
    for (let i = 0; i < rules.length; i++) {
      const rule = rules[i];
      if (!isAcceptAction(rule)) continue;
      const raw = String(rule.raw || '');
      const mac = raw.match(/--mac-source\s+([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})/) ||
                  raw.match(/\bether\s+saddr\s+([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})/);
      if (!mac) continue;
      findings.push({
        id: 'mac-based-trust',
        severity: 'warning',
        table: table.name,
        tableFamily: table.family || null,
        chain: chain.name,
        ruleIdx: i,
        title: `Trusts a spoofable MAC address (${mac[1]})`,
        details: 'A MAC is identification, not authentication: every device on the segment sees it (ARP/NDP) and can wear it with one `ip link set address` command. Note the IP-level smells still judge this rule as unrestricted — a MAC match is not a source restriction. Scope the rule to an IP/subnet (or authenticate for real: keys, 802.1X); blocking a known-bad MAC is fine, trusting one is not.'
      });
    }
  }

  // ── masquerade-any-source ──────────────────────────────────────────
  // A POSTROUTING MASQUERADE / SNAT with no source restriction rewrites
  // every packet the host forwards, not just the LAN / VPN subnet it was
  // meant for. Combined with a permissive FORWARD chain this turns the
  // host into an anonymizing relay: anything routed through it leaves
  // wearing its address. Restricting the source is nearly free and
  // self-documents which network the NAT is for.
  function detectMasqueradeAnySource(table, chain, findings) {
    const rules = chain.rules || [];
    for (let i = 0; i < rules.length; i++) {
      const rule = rules[i];
      const action = String(rule.action || '').toUpperCase();
      if (action !== 'MASQUERADE' && action !== 'SNAT') continue;
      if (!isSourceAny(rule)) continue;
      findings.push({
        id: 'masquerade-any-source',
        severity: 'warning',
        table: table.name,
        tableFamily: table.family || null,
        chain: chain.name,
        ruleIdx: i,
        title: `${action} without a source restriction NATs anything the host forwards`,
        details: `${rule.raw || ''} — with no \`-s\` (or nft \`ip saddr\`) every forwarded packet is source-rewritten to this host's address. Restrict it to the subnet it is meant to serve (e.g. \`-s 10.8.0.0/24\`).`
      });
    }
  }

  function isNatPostroutingChain(table, chain, format) {
    if (format === 'nftables') {
      return chain.builtIn && chain.hook === 'postrouting';
    }
    return String(table.name || '').toLowerCase() === 'nat'
        && String(chain.name || '').toUpperCase() === 'POSTROUTING';
  }

  // ── exposed-via-dnat ───────────────────────────────────────────────
  // A port-forward from the public side to an admin port (ssh, mysql,
  // rdp, postgres, redis, mongodb) is a NAT rule like:
  //   -A PREROUTING -p tcp --dport 2222 -j DNAT --to-destination 10.0.0.5:22
  // If the rule has no source restriction (`-s` / nft `ip saddr`), the
  // admin service ends up reachable from anyone who can hit the public
  // interface — the DNAT silently bypasses any default-deny intuition
  // the operator may have for the filter chain. The rewritten dport is
  // what we care about, not the externally-visible dport, so we reuse
  // the trace engine's extractDnatRewrite to discover the real target.
  function detectExposedViaDnat(table, chain, findings) {
    if (!window.FirewallScope || typeof window.FirewallScope.extractDnatRewrite !== 'function') return;
    const extract = window.FirewallScope.extractDnatRewrite;
    const rules = chain.rules || [];
    for (let i = 0; i < rules.length; i++) {
      const rule = rules[i];
      const action = String(rule.action || '').toUpperCase();
      if (action !== 'DNAT' && action !== 'REDIRECT') continue;
      const rewrite = extract(rule);
      if (!rewrite || rewrite.dport == null) continue;
      const service = ADMIN_PORTS[rewrite.dport];
      if (!service) continue;
      if (!isSourceAny(rule)) continue;
      const targetLabel = rewrite.destination
        ? `${rewrite.destination}:${rewrite.dport}`
        : `:${rewrite.dport}`;
      findings.push({
        id: 'exposed-via-dnat',
        severity: 'warning',
        table: table.name,
        tableFamily: table.family || null,
        chain: chain.name,
        ruleIdx: i,
        title: `Port-forward exposes ${service} (port ${rewrite.dport}) without source restriction`,
        details: `Rewrites to ${targetLabel}. With no \`-s\` (or nft \`ip saddr\`) the admin port is reachable from any source that can hit this interface. Consider restricting the source to your management network.`
      });
    }
  }

  function isNatPreroutingChain(table, chain, format) {
    if (format === 'nftables') {
      return chain.builtIn && chain.hook === 'prerouting';
    }
    return String(table.name || '').toLowerCase() === 'nat'
        && String(chain.name || '').toUpperCase() === 'PREROUTING';
  }

  window.FirewallScope = window.FirewallScope || {};
  window.FirewallScope.lint = lint;
})();
