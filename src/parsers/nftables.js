(function () {
  'use strict';

  const SIMPLE_VERBS = ['accept', 'drop', 'reject', 'return', 'queue', 'continue'];
  const COMPOUND_RES = [
    { re: /\bjump\s+(\S+)$/i,        verb: 'JUMP',       jumpToChain: true,  goto: false },
    { re: /\bgoto\s+(\S+)$/i,        verb: 'GOTO',       jumpToChain: true,  goto: true  },
    { re: /\bredirect(?:\s+to\s+(:?\S+))?$/i, verb: 'REDIRECT' },
    { re: /\bdnat(?:\s+to\s+(\S+))?$/i, verb: 'DNAT' },
    { re: /\bsnat(?:\s+to\s+(\S+))?$/i, verb: 'SNAT' },
    { re: /\bmasquerade$/i,          verb: 'MASQUERADE' }
  ];

  function parseNftRuleset(text) {
    const lines = text.split('\n');
    const tables = [];
    const warnings = [];

    let currentTable = null;
    let currentChain = null;
    let depth = 0;

    for (let i = 0; i < lines.length; i++) {
      const raw = lines[i];
      let line = raw.trim();
      if (!line) continue;
      if (line.startsWith('#')) continue;

      const hashIdx = indexOfStandaloneHash(line);
      if (hashIdx >= 0) line = line.slice(0, hashIdx).trim();
      if (!line) continue;

      if (line === '}') {
        if (depth === 2) { currentChain = null; depth = 1; }
        else if (depth === 1) { currentTable = null; depth = 0; }
        continue;
      }

      if (depth === 0) {
        const m = line.match(/^table\s+(\S+)\s+(\S+)\s*\{/);
        if (m) {
          currentTable = { name: m[2], family: m[1], chains: [] };
          tables.push(currentTable);
          depth = 1;
          continue;
        }
        warnings.push(`Line ${i + 1}: unrecognized top-level — "${raw}"`);
        continue;
      }

      if (depth === 1) {
        const m = line.match(/^chain\s+(\S+)\s*\{/);
        if (m) {
          currentChain = {
            name: m[1],
            policy: null,
            builtIn: false,
            hook: null,
            priority: null,
            rules: []
          };
          currentTable.chains.push(currentChain);
          depth = 2;
          continue;
        }
        continue;
      }

      if (depth === 2) {
        const typeMatch = line.match(/^type\s+(\S+)\s+hook\s+(\S+)\s+priority\s+([^;]+);?/);
        if (typeMatch) {
          currentChain.builtIn = true;
          currentChain.hook = typeMatch[2];
          currentChain.priority = typeMatch[3].trim();
          const policyInLine = line.match(/policy\s+([a-zA-Z]+);?\s*$/);
          if (policyInLine) currentChain.policy = policyInLine[1].toUpperCase();
          continue;
        }
        const policyMatch = line.match(/^policy\s+([a-zA-Z]+);?\s*$/);
        if (policyMatch) {
          currentChain.policy = policyMatch[1].toUpperCase();
          continue;
        }
        currentChain.rules.push(parseNftRule(line, raw));
      }
    }

    return { format: 'nftables', tables, warnings };
  }

  function indexOfStandaloneHash(line) {
    let inQuote = false;
    for (let i = 0; i < line.length; i++) {
      const c = line[i];
      if (c === '"') inQuote = !inQuote;
      if (c === '#' && !inQuote) return i;
    }
    return -1;
  }

  function parseNftRule(body, raw) {
    let comment = null;
    const commentMatch = body.match(/\bcomment\s+"([^"]+)"/);
    if (commentMatch) comment = commentMatch[1];
    let cleaned = body.replace(/\s*comment\s+"[^"]+"\s*;?\s*$/, '').trim();
    cleaned = cleaned.replace(/;\s*$/, '').trim();

    let action = null;
    let actionDetail = null;
    let isGoto = false;
    let isJumpToChain = false;

    for (const c of COMPOUND_RES) {
      const m = cleaned.match(c.re);
      if (m) {
        if (c.jumpToChain) {
          action = m[1];
          actionDetail = null;
          isGoto = !!c.goto;
          isJumpToChain = true;
        } else {
          action = c.verb;
          actionDetail = m[1] || null;
        }
        cleaned = cleaned.replace(c.re, '').trim();
        break;
      }
    }

    if (!action) {
      for (const v of SIMPLE_VERBS) {
        const re = new RegExp(`(?:^|\\s)${v}\\s*$`, 'i');
        if (re.test(cleaned)) {
          action = v.toUpperCase();
          cleaned = cleaned.replace(re, '').trim();
          break;
        }
      }
    }

    return {
      match: cleaned,
      action,
      actionDetail,
      isGoto,
      isJumpToChain,
      comment,
      raw,
      tokens: extractNftTokens(cleaned)
    };
  }

  function extractNftTokens(match) {
    const t = {};
    const protoDport = match.match(/(tcp|udp|sctp|dccp)\s+dport\s+(\{[^}]+\}|\S+)/);
    if (protoDport) { t.protocol = protoDport[1]; t.dport = protoDport[2]; }
    const protoSport = match.match(/(tcp|udp|sctp|dccp)\s+sport\s+(\{[^}]+\}|\S+)/);
    if (protoSport) { t.protocol = t.protocol || protoSport[1]; t.sport = protoSport[2]; }
    const saddr = match.match(/ip6?\s+saddr\s+(\S+)/);
    if (saddr) t.source = saddr[1];
    const daddr = match.match(/ip6?\s+daddr\s+(\S+)/);
    if (daddr) t.destination = daddr[1];
    const iifname = match.match(/iifname\s+"?([^"\s]+)"?/);
    if (iifname) t.iface_in = iifname[1];
    const oifname = match.match(/oifname\s+"?([^"\s]+)"?/);
    if (oifname) t.iface_out = oifname[1];
    const ctstate = match.match(/ct\s+state\s+([\w,]+)/);
    if (ctstate) t.ctstate = ctstate[1];
    return t;
  }

  window.parseNftRuleset = parseNftRuleset;
})();
