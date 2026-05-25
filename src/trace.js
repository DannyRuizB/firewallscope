// FirewallScope trace-a-packet — simulates how a single packet flows through
// the INPUT chain of the filter table, returns the verdict and a step-by-step
// log of which rules matched, which were skipped, which jumps were taken.
// Strictly client-side, single chain entry point for v0.5; FORWARD / OUTPUT
// and the full PREROUTING/mangle/raw pipeline are out of scope.
(function () {
  'use strict';

  const MAX_DEPTH = 50;

  function trace(result, packet) {
    const report = {
      verdict: null,
      finalRule: null,
      steps: [],
      visitedChains: [],   // ordered list of "table::chain" strings
      jumpedEdges: [],     // ordered list of "table::from -> table::to" strings
      warnings: [],
      error: null
    };
    if (!result || !result.tables || result.error) {
      report.error = (result && result.error) || 'no parsed ruleset';
      return report;
    }

    const direction = String(packet.direction || 'input').toLowerCase();
    if (direction !== 'input' && direction !== 'output' && direction !== 'forward') {
      report.error = `Unknown direction "${packet.direction}". Use 'input', 'output' or 'forward'.`;
      return report;
    }

    const filterTable = result.tables.find(t => isFilterTableName(t.name));
    if (!filterTable) {
      report.error = 'No filter table found — nothing to trace against.';
      return report;
    }
    const entryChain = filterTable.chains.find(c => isBuiltInDirectionChain(c, direction, result.format));
    if (!entryChain) {
      report.error = `Filter table has no ${direction.toUpperCase()}-like chain (built-in with hook ${direction}).`;
      return report;
    }

    // PREROUTING NAT happens before the routing decision feeds the packet
    // into filter/INPUT or filter/FORWARD, so we walk it first for both of
    // those directions and apply any DNAT/REDIRECT rewrite to the packet
    // that filter will actually see. OUTPUT-direction NAT (`nat/OUTPUT`)
    // is not modeled in v0.9.0 — only the inbound side, which covers the
    // typical port-forward use case.
    let workingPacket = packet;
    if (direction === 'input' || direction === 'forward') {
      workingPacket = walkNatPrerouting(result, packet, report);
    }

    const visitedSet = new Set();
    const finalVerdict = evaluateChain(filterTable, entryChain, workingPacket, 0, report, visitedSet, result.format);
    report.verdict = finalVerdict.kind === 'RETURN' ? 'NO_MATCH' : finalVerdict.kind;
    if (finalVerdict.table) {
      report.finalRule = { table: finalVerdict.table, chain: finalVerdict.chain, ruleIdx: finalVerdict.ruleIdx };
    }
    if (report.verdict === 'ACCEPT' && report.finalRule && report.finalRule.ruleIdx == null) {
      report.warnings.push(
        `Packet ACCEPTED by ${report.finalRule.chain} policy fall-through — no rule matched explicitly. Consider an explicit ACCEPT for expected traffic or a default-deny policy.`
      );
    }
    report.steps.push({ type: 'verdict', action: report.verdict });
    return report;
  }

  function evaluateChain(table, chain, packet, depth, report, visitedSet, format) {
    if (depth > MAX_DEPTH) {
      report.warnings.push(`Recursion limit reached at ${chain.name}; aborting trace.`);
      return { kind: 'DROP', table: table.name, chain: chain.name, ruleIdx: null };
    }
    const chainKey = `${table.name}::${chain.name}`;
    if (!visitedSet.has(chainKey)) {
      visitedSet.add(chainKey);
      report.visitedChains.push(chainKey);
    }
    report.steps.push({ type: 'enter-chain', table: table.name, chain: chain.name, depth });

    const rules = chain.rules || [];
    for (let i = 0; i < rules.length; i++) {
      const rule = rules[i];
      const mr = matchesPacket(rule, packet);
      if (mr.skipped) {
        report.steps.push({
          type: 'skip',
          table: table.name, chain: chain.name, ruleIdx: i,
          ruleRaw: rule.raw, reason: mr.reason, depth
        });
        report.warnings.push(`${chain.name} rule #${i + 1} skipped — ${mr.reason}`);
        continue;
      }
      if (!mr.matched) {
        report.steps.push({
          type: 'no-match',
          table: table.name, chain: chain.name, ruleIdx: i,
          ruleRaw: rule.raw, depth
        });
        continue;
      }

      const actionRaw = rule.action || '';
      const action = String(actionRaw).toUpperCase();
      report.steps.push({
        type: 'match',
        table: table.name, chain: chain.name, ruleIdx: i,
        ruleRaw: rule.raw, action, depth
      });

      if (action === 'ACCEPT' || action === 'DROP' || action === 'REJECT') {
        return { kind: action, table: table.name, chain: chain.name, ruleIdx: i };
      }
      if (action === 'RETURN') {
        return { kind: 'RETURN', table: table.name, chain: chain.name, ruleIdx: i };
      }
      if (rule.isJumpToChain) {
        // The target chain name lives in rule.action (original case);
        // rule.actionDetail is the leftover argument string after "-j NAME"
        // and is irrelevant for the trace.
        const targetName = actionRaw;
        const targetChain = table.chains.find(c => c.name === targetName);
        if (!targetChain) {
          report.warnings.push(`Jump target ${targetName} not found in table ${table.name}; treating as continue.`);
          continue;
        }
        const edgeKey = `${chainKey}->${table.name}::${targetName}`;
        report.jumpedEdges.push(edgeKey);
        report.steps.push({ type: 'jump', table: table.name, chain: chain.name, ruleIdx: i, jumpedTo: targetName, depth });
        const sub = evaluateChain(table, targetChain, packet, depth + 1, report, visitedSet, format);
        if (sub.kind === 'ACCEPT' || sub.kind === 'DROP' || sub.kind === 'REJECT') return sub;
        // RETURN (or fall-through, which we also map to RETURN below): continue evaluating the current chain at i+1.
        continue;
      }
      // Non-terminal action (LOG, NFLOG, MARK, COUNTER, MASQUERADE in nat, …): record and continue.
      // We deliberately don't whitelist — anything we don't recognise as terminal is treated as continue.
      report.steps.push({ type: 'log', table: table.name, chain: chain.name, ruleIdx: i, action, depth });
    }

    // Chain reached the end without a verdict.
    if (chain.builtIn !== false) {
      const policy = String(chain.policy || '').toUpperCase();
      if (policy === 'ACCEPT' || policy === 'DROP' || policy === 'REJECT') {
        report.steps.push({ type: 'policy', table: table.name, chain: chain.name, action: policy, depth });
        return { kind: policy, table: table.name, chain: chain.name, ruleIdx: null };
      }
      // No explicit policy on a built-in chain → default to ACCEPT (iptables built-in default).
      report.steps.push({ type: 'policy', table: table.name, chain: chain.name, action: 'ACCEPT', depth, reason: 'no explicit policy, defaulting to ACCEPT' });
      return { kind: 'ACCEPT', table: table.name, chain: chain.name, ruleIdx: null };
    }
    // User-defined chain fell through → implicit RETURN.
    report.steps.push({ type: 'return', table: table.name, chain: chain.name, reason: 'end-of-chain', depth });
    return { kind: 'RETURN' };
  }

  // ── match logic ────────────────────────────────────────────────────────

  function matchesPacket(rule, packet) {
    if (hasUnmodeledMatch(rule)) {
      return { matched: false, skipped: true, reason: 'rule has matches the simulator does not model (-i / -o / -m limit / -m recent / -m mark / -m mac / -m string / nft meter)' };
    }

    const t = rule.tokens || {};

    const ruleIif = extractIfaceFromRaw(rule.raw, 'in');
    if (ruleIif) {
      if (!packet.iif) return { matched: false };
      if (ruleIif !== packet.iif) return { matched: false };
    }
    const ruleOif = extractIfaceFromRaw(rule.raw, 'out');
    if (ruleOif) {
      if (!packet.oif) return { matched: false };
      if (ruleOif !== packet.oif) return { matched: false };
    }

    const ruleProto = normalizeProto(t.protocol || extractProtoFromRaw(rule.raw));
    if (ruleProto && ruleProto !== (packet.protocol || '').toLowerCase()) return { matched: false };

    if (t.source && !isAnyCidr(t.source)) {
      if (!packet.source) return { matched: false, skipped: true, reason: `rule restricts source to ${t.source} but the packet has no source IP filled in` };
      const r = ipInCidr(packet.source, t.source);
      if (r === 'indeterminate') return { matched: false, skipped: true, reason: `source CIDR ${t.source} could not be evaluated (IPv6 arithmetic is limited in this simulator)` };
      if (!r) return { matched: false };
    }
    if (t.destination && !isAnyCidr(t.destination)) {
      if (!packet.destination) return { matched: false, skipped: true, reason: `rule restricts destination to ${t.destination} but the packet has no destination IP filled in` };
      const r = ipInCidr(packet.destination, t.destination);
      if (r === 'indeterminate') return { matched: false, skipped: true, reason: `destination CIDR ${t.destination} could not be evaluated` };
      if (!r) return { matched: false };
    }
    if (t.dport) {
      if (packet.dport == null || packet.dport === '') return { matched: false };
      if (!portInExpr(+packet.dport, t.dport)) return { matched: false };
    }
    if (t.sport) {
      if (packet.sport == null || packet.sport === '') return { matched: false };
      if (!portInExpr(+packet.sport, t.sport)) return { matched: false };
    }

    const cts = ctState(rule);
    if (cts) {
      if (!packet.state) return { matched: false };
      const required = cts.toUpperCase().split(',');
      if (!required.includes(packet.state.toUpperCase())) return { matched: false };
    }

    return { matched: true };
  }

  // ── shared helpers (duplicated from linter.js to keep modules independent) ──

  function isFilterTableName(name) {
    if (!name) return true;
    return String(name).toLowerCase() === 'filter';
  }
  // direction is one of 'input' / 'output' / 'forward'. For nftables the
  // hook attribute on the chain is matched directly; for iptables / ip6tables
  // / ufw the chain is named INPUT / OUTPUT / FORWARD in upper-case.
  function isBuiltInDirectionChain(chain, direction, format) {
    if (format === 'nftables') return chain.builtIn && chain.hook === direction;
    return chain.name === direction.toUpperCase();
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
    if ((m = s.match(/(?:^|\s)-p\s+(\S+)/)))       return m[1].toLowerCase();
    if ((m = s.match(/\bmeta\s+l4proto\s+(\S+)/))) return m[1].toLowerCase();
    if ((m = s.match(/\bip6\s+nexthdr\s+(\S+)/)))  return m[1].toLowerCase();
    if ((m = s.match(/\bip\s+protocol\s+(\S+)/)))  return m[1].toLowerCase();
    return null;
  }
  function hasUnmodeledMatch(rule) {
    const raw = String(rule.raw || '');
    // Interfaces (-i / -o / iifname / oifname / iif / oif) are now modeled
    // explicitly in matchesPacket; removed from this list as of v0.8.0.
    if (/-m\s+(?:limit|recent|hashlimit|connlimit|owner|mark|mac|string|hexstring|set|policy|conntrack(?!\s+--ctstate))/.test(raw)) return true;
    if (/\b(?:limit\s+rate|meter\s)/.test(raw)) return true;
    return false;
  }

  // Pulls the interface name out of a rule. Supports iptables / ufw "-i eth0"
  // / "-o eth0" syntax and nftables "iifname \"eth0\"" / "iif eth0" /
  // "oifname \"eth0\"" / "oif eth0". Negation ("! -i lo"), comma sets and
  // wildcards are not handled — single literal interface only for v0.8.0.
  function extractIfaceFromRaw(raw, kind) {
    const s = String(raw || '');
    let m;
    if (kind === 'in') {
      if ((m = s.match(/(?:^|\s)-i\s+(\S+)/)))            return m[1];
      if ((m = s.match(/\biifname\s+"([^"]+)"/)))         return m[1];
      if ((m = s.match(/\biifname\s+([\w@.\-]+)/)))       return m[1];
      if ((m = s.match(/\biif\s+([\w@.\-]+)/)))           return m[1];
    } else {
      if ((m = s.match(/(?:^|\s)-o\s+(\S+)/)))            return m[1];
      if ((m = s.match(/\boifname\s+"([^"]+)"/)))         return m[1];
      if ((m = s.match(/\boifname\s+([\w@.\-]+)/)))       return m[1];
      if ((m = s.match(/\boif\s+([\w@.\-]+)/)))           return m[1];
    }
    return null;
  }
  function ctState(rule) {
    const raw = String(rule.raw || '');
    const m1 = raw.match(/-m\s+conntrack\s+--ctstate\s+([A-Z,_]+)/i) || raw.match(/--ctstate\s+([A-Z,_]+)/i);
    if (m1) return m1[1].toUpperCase().split(',').sort().join(',');
    const m2 = raw.match(/\bct\s+state\s+([A-Za-z,_\s]+?)(?:\s+(accept|drop|reject|return|jump|goto|log|counter|$)|$)/);
    if (m2) return m2[1].toLowerCase().replace(/\s+/g, '').split(',').filter(Boolean).sort().join(',').toUpperCase();
    return '';
  }
  function isAnyCidr(s) {
    const v = String(s || '').trim();
    return v === '' || v === '0.0.0.0/0' || v === '::/0' || /^any(where)?$/i.test(v);
  }

  // Returns true / false / 'indeterminate' (for v6 outside the trivial cases).
  function ipInCidr(ip, cidr) {
    if (!ip || !cidr) return false;
    const cParts = String(cidr).trim();
    if (cParts.includes(':')) {
      // IPv6: only trivial textual equality / unspecified prefix.
      if (cParts === '::/0') return true;
      return ip.trim() === cParts ? true : 'indeterminate';
    }
    const m = cParts.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)(?:\/(\d+))?$/);
    if (!m) return false;
    const cVal =
      (BigInt(+m[1]) << 24n) | (BigInt(+m[2]) << 16n) | (BigInt(+m[3]) <<  8n) | BigInt(+m[4]);
    const bits = m[5] !== undefined ? +m[5] : 32;
    const ipM = String(ip).trim().match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
    if (!ipM) return 'indeterminate';
    const iVal =
      (BigInt(+ipM[1]) << 24n) | (BigInt(+ipM[2]) << 16n) | (BigInt(+ipM[3]) <<  8n) | BigInt(+ipM[4]);
    if (bits === 0) return true;
    const shift = 32n - BigInt(bits);
    return (iVal >> shift) === (cVal >> shift);
  }

  function portInExpr(port, expr) {
    const str = String(expr).trim();
    const setM = str.match(/^\{([^}]+)\}$/);
    const inner = setM ? setM[1] : str;
    const parts = inner.includes(',') ? inner.split(',').map(s => s.trim()) : [inner];
    for (const part of parts) {
      const r = part.match(/^(\d+)[:\-](\d+)$/);
      if (r) {
        if (port >= +r[1] && port <= +r[2]) return true;
      } else if (/^\d+$/.test(part)) {
        if (port === +part) return true;
      }
    }
    return false;
  }

  // ── NAT PREROUTING walk ─────────────────────────────────────────────
  // Iterates nat/PREROUTING rules looking for the first DNAT / REDIRECT
  // that matches the packet. Applies the rewrite (destination IP and/or
  // dport) and exits the chain — DNAT in iptables semantically terminates
  // the nat-table chain for that packet, so we mirror that behavior. The
  // (possibly rewritten) packet is returned so the caller can hand it to
  // the filter chain.
  function walkNatPrerouting(result, packet, report) {
    const natTable = findNatTable(result);
    if (!natTable) return packet;
    const preChain = natTable.chains.find(c => isPreroutingChain(c, result.format));
    if (!preChain) return packet;

    report.steps.push({ type: 'enter-chain', table: natTable.name, chain: preChain.name, depth: 0 });
    const visitedKey = `${natTable.name}::${preChain.name}`;
    if (!report.visitedChains.includes(visitedKey)) report.visitedChains.push(visitedKey);

    const rules = preChain.rules || [];
    for (let i = 0; i < rules.length; i++) {
      const rule = rules[i];
      const mr = matchesPacket(rule, packet);
      if (mr.skipped) {
        report.steps.push({ type: 'skip', table: natTable.name, chain: preChain.name, ruleIdx: i, ruleRaw: rule.raw, reason: mr.reason, depth: 0 });
        continue;
      }
      if (!mr.matched) {
        report.steps.push({ type: 'no-match', table: natTable.name, chain: preChain.name, ruleIdx: i, ruleRaw: rule.raw, depth: 0 });
        continue;
      }
      const rewrite = extractDnatRewrite(rule);
      if (!rewrite) {
        report.steps.push({ type: 'match', table: natTable.name, chain: preChain.name, ruleIdx: i, ruleRaw: rule.raw, action: String(rule.action || '').toUpperCase(), depth: 0 });
        continue;
      }
      const rewritten = applyRewrite(packet, rewrite);
      report.steps.push({
        type: 'dnat',
        table: natTable.name, chain: preChain.name, ruleIdx: i,
        ruleRaw: rule.raw,
        before: { destination: packet.destination || null, dport: packet.dport != null ? packet.dport : null },
        after:  { destination: rewritten.destination || null, dport: rewritten.dport != null ? rewritten.dport : null },
        depth: 0
      });
      report.natPacket = { destination: rewritten.destination, dport: rewritten.dport };
      return rewritten;
    }
    return packet;
  }

  function findNatTable(result) {
    if (!result || !Array.isArray(result.tables)) return null;
    if (result.format === 'nftables') {
      // nft: any table that contains a chain of type "nat" hooked at prerouting.
      return result.tables.find(t =>
        (t.chains || []).some(c => c.builtIn && c.hook === 'prerouting')
      ) || null;
    }
    return result.tables.find(t => String(t.name || '').toLowerCase() === 'nat') || null;
  }
  function isPreroutingChain(chain, format) {
    if (format === 'nftables') return chain.builtIn && chain.hook === 'prerouting';
    return String(chain.name || '').toUpperCase() === 'PREROUTING';
  }

  // Recognizes DNAT and REDIRECT targets across iptables / nft syntaxes
  // and returns { destination?, dport? } or null when the rule is not a
  // rewrite or the rewrite target is too complex to model (ranges, sets,
  // load-balanced pools).
  function extractDnatRewrite(rule) {
    const raw = String(rule.raw || '');
    const action = String(rule.action || '').toUpperCase();

    // iptables: -j DNAT --to-destination IP[:PORT]  or  --to IP[:PORT]
    if (action === 'DNAT') {
      const m = raw.match(/--to-destination\s+([^\s]+)/) || raw.match(/--to\s+([^\s]+)/);
      if (!m) return null;
      return parseDnatTarget(m[1]);
    }
    // iptables: -j REDIRECT [--to-ports PORT] — rewrites dst to localhost on the same iface.
    if (action === 'REDIRECT') {
      const m = raw.match(/--to-ports?\s+(\d+)(?:[:\-]\d+)?/);
      const port = m ? +m[1] : null;
      const out = { destination: '127.0.0.1' };
      if (port != null) out.dport = port;
      return out;
    }
    // nft: "dnat to 192.168.1.10:8080" or "dnat ip to 192.168.1.10"
    let m;
    if ((m = raw.match(/\bdnat\s+(?:ip\s+|ip6\s+)?to\s+([^\s,;]+)/))) {
      return parseDnatTarget(m[1]);
    }
    // nft: "redirect to :8080" or "redirect to 8080"
    if ((m = raw.match(/\bredirect\s+to\s+:?(\d+)\b/))) {
      return { destination: '127.0.0.1', dport: +m[1] };
    }
    return null;
  }

  // Parses an iptables-style DNAT target like "192.168.1.10", "192.168.1.10:8080"
  // or "10.0.0.5". Anything fancier (port ranges, multiple targets) yields
  // null so the trace can fall back to a plain match step.
  function parseDnatTarget(s) {
    const str = String(s).trim();
    // Pure :port form (rare in DNAT but valid in REDIRECT)
    if (str.startsWith(':')) {
      const p = +str.slice(1);
      if (!Number.isFinite(p)) return null;
      return { dport: p };
    }
    // Range or list — bail
    if (/[,\-]\d+\b/.test(str.replace(/^\d+\.\d+\.\d+\.\d+/, ''))) return null;
    const m = str.match(/^(\d+\.\d+\.\d+\.\d+)(?::(\d+))?$/);
    if (!m) return null;
    const out = { destination: m[1] };
    if (m[2]) out.dport = +m[2];
    return out;
  }

  function applyRewrite(packet, rewrite) {
    const out = Object.assign({}, packet);
    if (rewrite.destination) out.destination = rewrite.destination;
    if (rewrite.dport != null) out.dport = rewrite.dport;
    return out;
  }

  window.FirewallScope = window.FirewallScope || {};
  window.FirewallScope.trace = trace;
})();
