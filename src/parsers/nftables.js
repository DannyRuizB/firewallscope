(function () {
  'use strict';

  const SIMPLE_VERBS = ['accept', 'drop', 'reject', 'return', 'queue', 'continue'];
  const COMPOUND_RES = [
    { re: /\bjump\s+(\S+)$/i,        verb: 'JUMP',       jumpToChain: true,  goto: false },
    { re: /\bgoto\s+(\S+)$/i,        verb: 'GOTO',       jumpToChain: true,  goto: true  },
    { re: /\bredirect(?:\s+to\s+(:?\S+))?$/i, verb: 'REDIRECT' },
    { re: /\bdnat(?:\s+to\s+(\S+))?$/i, verb: 'DNAT' },
    { re: /\bsnat(?:\s+to\s+(\S+))?$/i, verb: 'SNAT' },
    { re: /\bmasquerade$/i,          verb: 'MASQUERADE' },
    // `reject with tcp reset` / `reject with icmp type port-unreachable` /
    // `reject with icmpx type …` — a REJECT verdict carrying its reject type.
    // Before this, only a bare `reject` was recognised and the rule ended up
    // with NO action at all (the smell that reads the reject type needs it).
    { re: /\breject\s+with\s+(.+)$/i, verb: 'REJECT' }
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
            type: null,
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
          // `type nat|filter|route` — the smell that judges conntrack state in a nat chain needs it.
          currentChain.type = typeMatch[1];
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
    // The transport protocol when it is named WITHOUT a port match:
    // `ip protocol udp`, `ip6 nexthdr udp`, `meta l4proto udp`, or an
    // `icmp type` / `icmpv6 type` match (which pins the protocol to icmp).
    // Kept apart from `protocol` (set by the port matches above) so the
    // smells that pair protocol WITH a port keep their exact meaning;
    // negated forms (`!=`) are deliberately not recorded.
    const l4 = match.match(/(?:ip\s+protocol|ip6\s+nexthdr|meta\s+l4proto)\s+(?!!=)(\w+)/);
    if (l4) t.l4proto = l4[1];
    else if (/(?:^|\s)icmpv6\s+type\s/.test(match)) t.l4proto = 'icmpv6';
    else if (/(?:^|\s)icmp\s+type\s/.test(match)) t.l4proto = 'icmp';
    // `tcp flags & MASK == COMP` (or `!=`), the mask-and-compare form. Each
    // side is a flag name, a parenthesised `(a | b)` set or a number; the
    // bare `tcp flags syn` / `tcp flags == syn` forms have no mask and are
    // deliberately not recorded.
    const tf = match.match(/tcp\s+flags\s*&\s*(\([^)]*\)|\S+)\s*(==|!=)\s*(\([^)]*\)|\S+)/);
    if (tf) { t.tcp_flags_mask = tf[1]; t.tcp_flags_comp = tf[3]; t.tcp_flags_negated = tf[2] === '!='; }
    return t;
  }

  window.parseNftRuleset = parseNftRuleset;
})();
