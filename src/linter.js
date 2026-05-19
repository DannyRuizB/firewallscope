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

  window.FirewallScope = window.FirewallScope || {};
  window.FirewallScope.lint = lint;
})();
