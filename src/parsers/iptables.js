(function () {
  'use strict';

  const RESERVED_TARGETS = new Set([
    'ACCEPT', 'DROP', 'REJECT', 'RETURN', 'LOG', 'QUEUE', 'NFLOG',
    'MARK', 'CONNMARK', 'TOS', 'TTL', 'MASQUERADE', 'SNAT', 'DNAT',
    'REDIRECT', 'NETMAP', 'TPROXY', 'NOTRACK', 'AUDIT', 'CT',
    'CHECKSUM', 'CLASSIFY', 'CLUSTERIP', 'DSCP', 'ECN', 'HMARK',
    'IDLETIMER', 'LED', 'RATEEST', 'SECMARK', 'SET', 'TCPMSS',
    'TCPOPTSTRIP', 'TEE', 'TRACE'
  ]);

  function parseIptablesSave(text, formatLabel) {
    const lines = text.split('\n');
    const tables = [];
    const warnings = [];
    let current = null;

    for (let i = 0; i < lines.length; i++) {
      const raw = lines[i];
      const line = raw.trim();

      if (!line || line.startsWith('#')) continue;

      if (line.startsWith('*')) {
        current = { name: line.slice(1).trim(), chains: [] };
        tables.push(current);
        continue;
      }

      if (line === 'COMMIT') {
        current = null;
        continue;
      }

      if (!current) {
        warnings.push(`Line ${i + 1}: rule outside any table — "${raw}"`);
        continue;
      }

      if (line.startsWith(':')) {
        const m = line.match(/^:(\S+)\s+(\S+)/);
        if (m) {
          const name = m[1];
          const policyTok = m[2];
          const policy = policyTok === '-' ? null : policyTok;
          if (!current.chains.find(c => c.name === name)) {
            current.chains.push({
              name,
              policy,
              builtIn: policy !== null,
              rules: []
            });
          }
        } else {
          warnings.push(`Line ${i + 1}: malformed chain declaration — "${raw}"`);
        }
        continue;
      }

      if (line.startsWith('-N ')) {
        const name = line.split(/\s+/)[1];
        if (!current.chains.find(c => c.name === name)) {
          current.chains.push({ name, policy: null, builtIn: false, rules: [] });
        }
        continue;
      }

      if (line.startsWith('-A ') || line.startsWith('-I ')) {
        const tokens = line.split(/\s+/);
        const chainName = tokens[1];
        let chain = current.chains.find(c => c.name === chainName);
        if (!chain) {
          chain = { name: chainName, policy: null, builtIn: false, rules: [] };
          current.chains.push(chain);
        }
        const rest = tokens.slice(2).join(' ');
        chain.rules.push(parseRule(rest, raw));
        continue;
      }

      warnings.push(`Line ${i + 1}: unrecognized — "${raw}"`);
    }

    return { format: formatLabel || 'iptables', tables, warnings };
  }

  function parseRule(body, raw) {
    let action = null;
    let actionDetail = null;
    let isGoto = false;
    let comment = null;

    const commentDouble = body.match(/--comment\s+"([^"]+)"/);
    const commentSingle = !commentDouble && body.match(/--comment\s+(\S+)/);
    if (commentDouble) comment = commentDouble[1];
    else if (commentSingle) comment = commentSingle[1];

    const gotoMatch = body.match(/-g\s+(\S+)(.*)$/);
    const jumpMatch = body.match(/-j\s+(\S+)(.*)$/);
    if (gotoMatch) {
      action = gotoMatch[1];
      actionDetail = gotoMatch[2].trim() || null;
      isGoto = true;
    } else if (jumpMatch) {
      action = jumpMatch[1];
      actionDetail = jumpMatch[2].trim() || null;
    }

    const matchPart = body
      .replace(/-j\s+\S+.*$/, '')
      .replace(/-g\s+\S+.*$/, '')
      .replace(/-m\s+comment\s+--comment\s+"[^"]+"/, '')
      .replace(/-m\s+comment\s+--comment\s+\S+/, '')
      .replace(/\s+/g, ' ')
      .trim();

    return {
      match: matchPart,
      action,
      actionDetail,
      isGoto,
      isJumpToChain: action !== null && !RESERVED_TARGETS.has(action),
      comment,
      raw,
      tokens: extractTokens(matchPart)
    };
  }

  function extractTokens(match) {
    const t = {};
    const grab = (re, key) => {
      const m = match.match(re);
      if (m) t[key] = m[1];
    };
    grab(/-p\s+(\S+)/, 'protocol');
    grab(/--dport\s+(\S+)/, 'dport');
    grab(/--sport\s+(\S+)/, 'sport');
    grab(/(?:^|\s)-s\s+(\S+)/, 'source');
    grab(/--source\s+(\S+)/, 'source');
    grab(/(?:^|\s)-d\s+(\S+)/, 'destination');
    grab(/--destination\s+(\S+)/, 'destination');
    grab(/(?:^|\s)-i\s+(\S+)/, 'iface_in');
    grab(/(?:^|\s)-o\s+(\S+)/, 'iface_out');
    grab(/--state\s+(\S+)/, 'state');
    grab(/--ctstate\s+(\S+)/, 'ctstate');
    grab(/--to-destination\s+(\S+)/, 'to_destination');
    grab(/--to-source\s+(\S+)/, 'to_source');
    grab(/--to-ports\s+(\S+)/, 'to_ports');
    return t;
  }

  window.parseIptablesSave = parseIptablesSave;
  window.IPTABLES_RESERVED_TARGETS = RESERVED_TARGETS;
})();
