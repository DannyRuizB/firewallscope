// FirewallScope linter — detects common firewall smells on the parsed IR.
// Each finding carries a severity (error / warning / info), a smell id, the
// chain it points at, and (when applicable) the rule index inside that chain.
// All detectors are pure functions over the parser output; the linter never
// reads raw text, only the structured tokens parsed earlier.
(function () {
  'use strict';

  const ADMIN_PORTS = {
    22:    'ssh',
    23:    'telnet',
    3306:  'mysql',
    3389:  'rdp',
    5432:  'postgres',
    6379:  'redis',
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
        }
        scanChainRules(chain, table, findings);
        detectShadowedRules(chain, table, findings, result.format);
        if (isFilterTable) {
          detectFallthroughAccept(result, chain, table, result.format, findings);
        }
      }
    }

    return summarize(findings);
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

  function scanChainRules(chain, table, findings) {
    const isBuiltIn = chain.builtIn !== false; // many parsers omit the flag for built-ins
    for (let i = 0; i < chain.rules.length; i++) {
      const rule = chain.rules[i];
      if (!isAcceptAction(rule)) continue;
      if (!isSourceAny(rule)) continue;

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

  // Only the filter table (and its variants across formats) actually drops
  // packets. nat / mangle / raw / security chains with policy ACCEPT are
  // normal and must not be flagged for missing default-deny.
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
    const range = inner.match(/^(\d+)[:\-](\d+)$/);
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

  // ── shadow detection ─────────────────────────────────────────────────
  // For each terminal rule N, check whether any earlier terminal rule M in
  // the same chain already captures every packet that N matches. Strict
  // subset semantics on protocol / source / destination / dport / sport;
  // jumps are not considered terminal (they could RETURN); rules with
  // divergent ct-state markers are not comparable.

  function detectShadowedRules(chain, table, findings, format) {
    const rules = chain.rules || [];
    for (let j = 1; j < rules.length; j++) {
      const N = rules[j];
      if (!isTerminalAction(N)) continue;
      for (let i = 0; i < j; i++) {
        const M = rules[i];
        if (!isTerminalAction(M)) continue;
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
    if (nP.family === 'v6') {
      // Avoid building a v6 BigInt parser for v0.4.1 — only accept the trivial
      // cases: identical text or M is the all-zeroes default route.
      return nSrc.trim() === mSrc.trim();
    }
    if (nP.bits < mP.bits) return false;                // n's prefix is shorter → wider
    const totalBits = 32n;
    const shift = totalBits - BigInt(mP.bits);
    return (nP.value >> shift) === (mP.value >> shift);
  }
  function isAnyCidr(s) {
    const v = String(s || '').trim();
    return v === '' || v === '0.0.0.0/0' || v === '::/0' || /^any(where)?$/i.test(v);
  }
  function parseCidr(s) {
    const str = String(s).trim();
    if (str.includes(':')) {
      const m = str.match(/^([0-9a-f:]+)(?:\/(\d+))?$/i);
      if (!m) return null;
      return { family: 'v6', bits: m[2] !== undefined ? +m[2] : 128 };
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
      const r = part.match(/^(\d+)[:\-](\d+)$/);
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

  window.FirewallScope = window.FirewallScope || {};
  window.FirewallScope.lint = lint;
})();
