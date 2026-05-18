(function () {
  'use strict';

  function parseUfwStatus(text) {
    const lines = text.split('\n');
    const warnings = [];

    const defaults = parseDefaults(lines);

    const chains = [
      { name: 'INPUT',   policy: defaults.incoming, builtIn: true, rules: [] },
      { name: 'OUTPUT',  policy: defaults.outgoing, builtIn: true, rules: [] },
      { name: 'FORWARD', policy: defaults.routed,   builtIn: true, rules: [] }
    ];

    let headerIdx = -1;
    for (let i = 0; i < lines.length; i++) {
      const l = lines[i];
      if (/^\s*To\b/.test(l) && /\bAction\b/.test(l) && /\bFrom\b/.test(l)) {
        headerIdx = i;
        break;
      }
    }

    if (headerIdx < 0) {
      warnings.push('No "To ... Action ... From" header found — input may not be `ufw status verbose` output');
      return { format: 'ufw', tables: [{ name: 'filter', chains }], warnings };
    }

    for (let i = headerIdx + 2; i < lines.length; i++) {
      const raw = lines[i];
      const line = raw.trim();
      if (!line) continue;
      if (/^(Status|Logging|Default|New profiles):/i.test(line)) continue;

      const parsed = parseUfwRow(raw);
      if (!parsed) {
        warnings.push(`Line ${i + 1}: unrecognized row — "${raw}"`);
        continue;
      }
      const chain = chains.find(c => c.name === parsed.chainName);
      if (chain) chain.rules.push(parsed.rule);
    }

    return { format: 'ufw', tables: [{ name: 'filter', chains }], warnings };
  }

  function parseDefaults(lines) {
    const out = { incoming: 'ACCEPT', outgoing: 'ACCEPT', routed: 'DROP' };
    for (const raw of lines) {
      const m = raw.trim().match(/^Default:\s*(.+)/);
      if (!m) continue;
      const parts = m[1].split(',').map(s => s.trim());
      for (const p of parts) {
        const pm = p.match(/^(\w+)\s+\((\w+)\)/);
        if (!pm) continue;
        const verb = pm[1].toLowerCase();
        const dir = pm[2].toLowerCase();
        const policy = verb === 'deny'    ? 'DROP'
                     : verb === 'reject'  ? 'REJECT'
                     : verb === 'allow'   ? 'ACCEPT'
                     : verb === 'disabled' ? null
                     : verb.toUpperCase();
        if (dir === 'incoming')      out.incoming = policy;
        else if (dir === 'outgoing') out.outgoing = policy;
        else if (dir === 'routed')   out.routed = policy;
      }
      break;
    }
    return out;
  }

  function parseUfwRow(raw) {
    const cols = raw.split(/\s{2,}/).map(s => s.trim()).filter(Boolean);
    if (cols.length < 3) return null;

    const to = cols[0];
    const action = cols[1];
    const from = cols.slice(2).join(' ');

    const actMatch = action.match(/^(ALLOW|DENY|REJECT|LIMIT)\s+(IN|OUT|FWD|FORWARD|ROUTED)\b/i);
    if (!actMatch) return null;

    const ufwAction = actMatch[1].toUpperCase();
    const dir = actMatch[2].toUpperCase();

    const chainName =
      (dir === 'OUT')                                       ? 'OUTPUT'  :
      (dir === 'FWD' || dir === 'FORWARD' || dir === 'ROUTED') ? 'FORWARD' :
                                                              'INPUT';

    const iptAction =
      ufwAction === 'ALLOW'  ? 'ACCEPT' :
      ufwAction === 'DENY'   ? 'DROP'   :
      ufwAction === 'REJECT' ? 'REJECT' :
      ufwAction === 'LIMIT'  ? 'LIMIT'  : 'ACCEPT';

    const tokens = parseUfwTo(to);
    if (from && !/^Anywhere(\s+\(v6\))?$/i.test(from)) {
      tokens.source = from;
    }

    return {
      chainName,
      rule: {
        match: `to=${to}` + (from && from !== 'Anywhere' ? ` from=${from}` : ''),
        action: iptAction,
        actionDetail: null,
        isGoto: false,
        isJumpToChain: false,
        comment: null,
        raw,
        tokens
      }
    };
  }

  function parseUfwTo(to) {
    const t = {};
    const portProto = to.match(/(\S+)\/(tcp|udp)/i);
    if (portProto) {
      t.dport = portProto[1];
      t.protocol = portProto[2].toLowerCase();
    } else if (/^\d+$/.test(to)) {
      t.dport = to;
    }
    return t;
  }

  window.parseUfwStatus = parseUfwStatus;
})();
