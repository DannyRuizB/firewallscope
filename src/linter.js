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
          flagIcmpPmtudBlocked(chain, table, findings, result.format);
        }
        scanChainRules(chain, table, findings);
        if (isFilterTable) {
          detectOverbroadSource(chain, table, findings);
          detectBogonSourceAccept(chain, table, findings);
          detectMacBasedTrust(chain, table, findings, result.format);
          detectAdminPortNoRateLimit(chain, table, findings, result.format);
          detectRateLimitNotPerSource(chain, table, findings, result.format);
          detectRateLimitDropInverted(chain, table, findings, result.format);
          detectRateLimitAcceptInverted(chain, table, findings, result.format);
          detectAllowUnderDefaultAllow(chain, table, findings, result.format);
          detectDenyUnderDefaultDeny(chain, table, findings, result.format);
        }
        detectUnlimitedLog(chain, table, findings, result.format);
        detectLogTcpSequence(chain, table, findings, result.format);
        detectLogWithoutPrefix(chain, table, findings, result.format);
        if (isFilterTable) {
          detectUnlimitedIcmpEcho(chain, table, findings, result.format);
        }
        detectDuplicateRules(chain, table, findings, result.format);
        detectShadowedRules(chain, table, findings, result.format);
        detectRuleAfterPolicyDrop(chain, table, findings);
        detectUnreachableAfterAcceptAll(chain, table, findings);
        if (isFilterTable) {
          detectFallthroughAccept(result, chain, table, result.format, findings);
        }
        if (isNatPreroutingChain(table, chain, result.format)) {
          detectExposedViaDnat(table, chain, findings);
          detectDnatUnscoped(table, chain, findings);
          detectDnatToLoopback(table, chain, findings);
        }
        if (isNatPostroutingChain(table, chain, result.format)) {
          detectMasqueradeAnySource(table, chain, findings);
        }
      }
      detectUnusedChains(table, findings, result.format);
      if (isFilterTable) {
        detectUnrestrictedEgress(table, findings, result.format);
        detectSourcePortTrust(table, findings, result.format);
        detectUdpAmplifierExposed(table, findings, result.format);
      }
    }

    if (result.format === 'nftables') {
      detectIpv6Unfiltered(result, findings);
    }
    detectDnatForwardBlocked(result, findings);
    detectDnatNoHairpin(result, findings);
    detectDockerUserUnfiltered(result, findings);
    detectNotrackDefeatsStateMatch(result, findings);
    detectNotrackOneWay(result, findings);
    detectRecentOneWay(result, findings);
    detectPortMatchWithoutProtocol(result, findings);
    detectRejectTypeMismatch(result, findings);
    detectPortMatchProtocolMismatch(result, findings);
    detectNatStateMatchDead(result, findings);
    detectTcpFlagsNeverMatch(result, findings);
    detectTcpOptionWithoutTcp(result, findings);
    detectIcmpMatchWithoutIcmp(result, findings);
    detectConntrackHelperEnabled(result, findings);

    return summarize(findings);
  }

  // ── conntrack-helper-enabled ────────────────────────────────────────
  // An application-layer conntrack helper (ALG) widens the firewall on its
  // own, at runtime, from data it reads inside the connection. The FTP
  // helper is the textbook case: it parses the cleartext `PORT`/`PASV`
  // exchange and opens a RELATED pinhole to whatever address:port it saw —
  // so a deny-postured ruleset that accepts RELATED (almost all do) can be
  // steered into opening arbitrary high ports by anyone who can talk to the
  // FTP control channel. The same class covers the SIP, H.323, IRC and TFTP
  // helpers. The mechanism is enabled three ways, all detected here:
  //   iptables raw/CT:  `-j CT --helper ftp`  (assign a helper to a flow)
  //   iptables filter:  `-m helper --helper ftp`  (match on a helped flow)
  //   nft:              `ct helper set "ftp"`
  // Warn, not error: a legacy FTP server sometimes genuinely needs its
  // helper — but it must be scoped to that one server and that one port,
  // and modern deployments should prefer explicit rules or FTPS/SFTP. The
  // finding names the helper so an operator can see whether it's the one
  // service they meant or a blanket enable.
  function detectConntrackHelperEnabled(result, findings) {
    for (const table of result.tables) {
      for (const chain of table.chains) {
        chain.rules.forEach((rule, idx) => {
          const helper = conntrackHelperName(rule, result.format);
          if (!helper) return;
          findings.push({
            id: 'conntrack-helper-enabled',
            severity: 'warning',
            table: table.name,
            tableFamily: table.family || null,
            chain: chain.name,
            ruleIdx: idx,
            title: `enables the ${helper} conntrack helper (dynamic pinholes from connection data)`,
            details: `The ${helper} application-layer helper widens the firewall at runtime from data it reads inside the connection — the FTP helper's class is famous for it: it parses the cleartext control channel and opens a RELATED pinhole to the address and port it sees there, so any ruleset that accepts RELATED (almost all do) can be steered into opening arbitrary ports by whoever can reach the control channel. Enable a helper only for the one legacy server that needs it, scoped to its address and port; prefer FTPS/SFTP (or protocol-native rules) where you can. If nothing here needs an ALG, drop the \`${result.format === 'nftables' ? 'ct helper set' : rule.action === 'CT' ? '-j CT --helper' : '-m helper'}\` rule entirely.`
          });
        });
      }
    }
  }

  // The helper name if this rule enables/matches a conntrack helper, else
  // null. iptables: the CT target's `--helper X`, or an `-m helper --helper
  // X` match. nft: `ct helper set "X"`. Quotes are stripped; a custom name
  // (ftp-2121) is kept as written so the operator sees their own label.
  function conntrackHelperName(rule, format) {
    if (format === 'nftables') {
      const m = (rule.raw || '').match(/\bct\s+helper\s+set\s+"?([\w.-]+)"?/i);
      return m ? m[1] : null;
    }
    if (rule.action === 'CT') {
      const m = (rule.actionDetail || '').match(/--helper\s+(\S+)/);
      if (m) return m[1].replace(/^"|"$/g, '');
    }
    const mm = (rule.match || '').match(/-m\s+helper\s+--helper\s+(\S+)/);
    return mm ? mm[1].replace(/^"|"$/g, '') : null;
  }

  // ── notrack-defeats-state-match ─────────────────────────────────────
  // The performance tweak that quietly turns off the firewall's memory for
  // one flow. A raw-table NOTRACK (iptables `-j NOTRACK` / `-j CT
  // --notrack`, nft `notrack`) is the standard tuning for high-pps
  // services — busy DNS and NTP boxes skip conntrack to survive — but an
  // untracked packet has conntrack state UNTRACKED: it is neither NEW nor
  // ESTABLISHED, so EVERY --ctstate / --state / `ct state` match in the
  // filter path is blind to it. The classic combination: raw/PREROUTING
  // NOTRACK udp/53 for performance, INPUT deny-postured with the textbook
  // `-p udp --dport 53 --ctstate NEW -j ACCEPT` — and the tuned port is
  // dead, because the accept that looks like it covers the traffic can
  // never match it. The only ctstate that matches is UNTRACKED itself.
  //
  // Fires per NOTRACK rule, and only when the pieces make the trap real:
  //  - the NOTRACK sits in an inbound raw hook (raw/PREROUTING, or an nft
  //    prerouting-hook chain containing `notrack`);
  //  - a family-matching filter INPUT chain is deny-postured — with an
  //    open INPUT the untracked packet gets in regardless;
  //  - at least one ACCEPT covering that traffic is state-qualified, and
  //    NO covering accept is stateless or matches UNTRACKED. A stateless
  //    accept works for untracked packets, so it dissolves the trap; no
  //    covering accept at all means the operator never meant to serve the
  //    port, and that is not this smell's story.
  function detectNotrackDefeatsStateMatch(result, findings) {
    if (result.format === 'ufw') return;
    for (const table of result.tables) {
      for (const chain of table.chains) {
        if (!isInboundNotrackChain(table, chain, result.format)) continue;
        chain.rules.forEach((rule, idx) => {
          if (!isNotrackRule(rule, result.format)) return;
          const input = findDenyPosturedInput(result, table);
          if (!input) return;
          const blind = coveringStateAccepts(input, rule);
          if (!blind) return;
          const traffic = notrackTrafficDesc(rule);
          const plural = blind.length === 1 ? 'accept' : 'accepts';
          findings.push({
            id: 'notrack-defeats-state-match',
            severity: 'warning',
            table: table.name,
            tableFamily: table.family || null,
            chain: chain.name,
            ruleIdx: idx,
            title: `NOTRACK on ${traffic} makes ${blind.length} state-qualified ${plural} blind to it`,
            details: `An untracked packet has conntrack state UNTRACKED — neither NEW nor ESTABLISHED — so the state-qualified ${plural} covering this traffic (\`${blind[0].raw.trim()}\`) can never match it, and the deny-postured INPUT drops the flow: the port looks served and is dead. The NOTRACK itself is usually right (conntrack costs real CPU per packet on high-rate services like DNS or NTP) — it is the accept that must stop asking conntrack about a flow conntrack never saw: match the untracked state explicitly (\`-m conntrack --ctstate UNTRACKED\`, nft \`ct state untracked\`) or accept the port statelessly (\`-p udp --dport 53 -j ACCEPT\` with no state match). And mind the reply direction: with conntrack out of the loop, a state-filtered OUTPUT needs the same treatment for the responses.`
          });
        });
      }
    }
  }

  function isInboundNotrackChain(table, chain, format) {
    if (format === 'nftables') return chain.hook === 'prerouting';
    return /^raw$/i.test(table.name) && /^PREROUTING$/i.test(chain.name);
  }

  function isNotrackRule(rule, format) {
    if (format === 'nftables') return /\bnotrack\b/i.test(rule.raw || '');
    if (rule.action === 'NOTRACK') return true;
    return rule.action === 'CT' && /--notrack\b/.test(rule.actionDetail || '');
  }

  function findDenyPosturedInput(result, rawTable) {
    for (const table of result.tables) {
      if (!isFilterTableName(table.name)) continue;
      if (!familiesOverlap(rawTable.family, table.family)) continue;
      for (const chain of table.chains) {
        if (!isBuiltInInputChain(chain, result.format)) continue;
        if (isDropPolicy(chain.policy) || isRejectPolicy(chain.policy) ||
            hasFinalCatchAllDrop(chain)) {
          return chain;
        }
      }
    }
    return null;
  }

  // nft's inet family sees both v4 and v6, so it overlaps everything;
  // iptables/ip6tables tables carry no family — the format splits them.
  function familiesOverlap(a, b) {
    if (!a || !b) return true;
    if (a === b) return true;
    return a === 'inet' || b === 'inet';
  }

  // The accepts in INPUT that cover the notracked traffic, when ALL of
  // them are state-qualified (the trap). A single covering accept that is
  // stateless or matches UNTRACKED returns null — it serves the flow.
  // Loopback accepts are excluded up front: `-i lo -j ACCEPT` is stateless
  // and portless, but it serves exactly nothing that arrives on a wire —
  // every real ruleset has one, and it must not dissolve the trap (the
  // sample caught precisely this before the exclusion existed).
  function coveringStateAccepts(chain, notrack) {
    const nProto = normalizeProto((notrack.tokens && notrack.tokens.protocol) || '');
    const nDport = (notrack.tokens && notrack.tokens.dport) || null;
    const blind = [];
    for (const rule of chain.rules) {
      if (!isAcceptAction(rule)) continue;
      if (isLoopbackRule(rule)) continue;
      const rProto = normalizeProto((rule.tokens && rule.tokens.protocol) || '');
      if (nProto && rProto && nProto !== rProto) continue;
      const rDport = (rule.tokens && rule.tokens.dport) || null;
      if (nDport && rDport && !dportCoversNotrack(rDport, nDport)) continue;
      const st = ruleStateSpec(rule);
      if (!st) return null;
      if (/untracked/i.test(st)) return null;
      blind.push(rule);
    }
    return blind.length ? blind : null;
  }

  function ruleStateSpec(rule) {
    const m = rule.match || '';
    const ct = m.match(/--ctstate\s+(\S+)/) || m.match(/--state\s+(\S+)/) ||
               m.match(/\bct\s+state\s+(\{[^}]*\}|[\w,]+)/i);
    return ct ? ct[1] : null;
  }

  // Conservative coverage: a numeric notracked port is checked against the
  // accept's dport expression; anything we can't model counts as NOT
  // covered, so an unreadable match never produces a false alarm.
  function dportCoversNotrack(acceptDport, notrackDport) {
    const n = String(notrackDport).trim();
    if (String(acceptDport).trim() === n) return true;
    if (/^\d+$/.test(n)) return portInDport(+n, String(acceptDport));
    return false;
  }

  function notrackTrafficDesc(rule) {
    const p = normalizeProto((rule.tokens && rule.tokens.protocol) || '');
    const d = (rule.tokens && rule.tokens.dport) || null;
    if (p && d) return `${p}/${d}`;
    if (p) return `all ${p}`;
    return 'all inbound traffic';
  }

  // ── notrack-one-way ─────────────────────────────────────────────────
  // A conntrack exemption is a PAIR, because a flow has two directions and
  // NOTRACK only ever matches packets crossing the hook it sits in. The
  // canonical high-pps recipe is raw/PREROUTING `udp dport 53 notrack`
  // PLUS raw/OUTPUT `udp sport 53 notrack`: skip tracking for the queries
  // coming in AND for the replies going out. Write only one half and the
  // other direction is still tracked — every reply is a locally-generated
  // packet conntrack has never seen, so it opens a FRESH entry with the
  // reply as the "original" direction: the conntrack table still fills at
  // line rate (exactly what the NOTRACK was deployed to prevent), and any
  // state-qualified rule on that path judges the replies as NEW forever
  // (an ESTABLISHED accept never matches them).
  //
  // Conservative on purpose: only port-qualified NOTRACK rules are judged
  // (a protocol we can read plus a dport or sport) — a bare `notrack` or an
  // unmodelable match stays silent. The mirror is matched by protocol with
  // dport<->sport swapped; a broader mirror (same protocol, no ports) also
  // satisfies it. ufw is exempt by construction (no raw-table syntax).
  function detectNotrackOneWay(result, findings) {
    if (result.format === 'ufw') return;
    const sides = collectNotrackRules(result);
    for (const entry of sides.inbound) {
      judgeNotrackMirror(entry, sides.outbound, 'inbound', findings);
    }
    for (const entry of sides.outbound) {
      judgeNotrackMirror(entry, sides.inbound, 'outbound', findings);
    }
  }

  function collectNotrackRules(result) {
    const inbound = [];
    const outbound = [];
    for (const table of result.tables) {
      for (const chain of table.chains) {
        const dirIn = isInboundNotrackChain(table, chain, result.format);
        const dirOut = isOutboundNotrackChain(table, chain, result.format);
        if (!dirIn && !dirOut) continue;
        chain.rules.forEach((rule, idx) => {
          if (!isNotrackRule(rule, result.format)) return;
          const entry = { table, chain, rule, idx };
          (dirIn ? inbound : outbound).push(entry);
        });
      }
    }
    return { inbound, outbound };
  }

  function isOutboundNotrackChain(table, chain, format) {
    if (format === 'nftables') return chain.hook === 'output';
    return /^raw$/i.test(table.name) && /^OUTPUT$/i.test(chain.name);
  }

  function judgeNotrackMirror(entry, opposite, direction, findings) {
    const t = entry.rule.tokens || {};
    const proto = normalizeProto(t.protocol || '');
    const dport = t.dport ? String(t.dport).trim() : null;
    const sport = t.sport ? String(t.sport).trim() : null;
    // Only judge what we can fully read: protocol plus at least one port.
    if (!proto || (!dport && !sport)) return;
    const mirrored = opposite.some((cand) => {
      const c = cand.rule.tokens || {};
      const cProto = normalizeProto(c.protocol || '');
      if (!cProto) return true; // a bare notrack covers everything
      if (cProto !== proto) return false;
      const cDport = c.dport ? String(c.dport).trim() : null;
      const cSport = c.sport ? String(c.sport).trim() : null;
      if (!cDport && !cSport) return true; // proto-wide mirror covers it
      if (dport && cSport !== dport) return false;
      if (sport && cDport !== sport) return false;
      return true;
    });
    if (mirrored) return;
    const traffic = dport ? `${proto}/${dport}` : `${proto} sport ${sport}`;
    const here = direction === 'inbound' ? 'inbound' : 'outbound';
    const missing = direction === 'inbound' ? 'outbound (raw/OUTPUT)' : 'inbound (raw/PREROUTING)';
    const mirrorSpec = direction === 'inbound'
      ? `${proto} sport ${dport || sport}`
      : `${proto} dport ${sport || dport}`;
    findings.push({
      id: 'notrack-one-way',
      severity: 'warning',
      table: entry.table.name,
      tableFamily: entry.table.family || null,
      chain: entry.chain.name,
      ruleIdx: entry.idx,
      title: `NOTRACK on ${traffic} covers only the ${here} direction — the ${direction === 'inbound' ? 'replies' : 'responses coming back'} are still tracked`,
      details: `NOTRACK only matches packets crossing the hook it sits in, and a flow has two directions. With just this ${here} half, every packet of the other direction opens a FRESH conntrack entry (conntrack never saw the flow, so the ${direction === 'inbound' ? 'reply' : 'response'} becomes the "original" direction of a new one): the conntrack table still fills at line rate — exactly what this exemption was deployed to prevent — and any state-qualified rule on that path judges those packets as NEW forever, never ESTABLISHED. Add the missing ${missing} half: a \`${mirrorSpec}\` NOTRACK, the second line of the canonical recipe.`
    });
  }

  // ── recent-one-way ──────────────────────────────────────────────────
  // `-m recent` is a two-line recipe, and each half is useless alone. The
  // canonical ssh brute-force limiter:
  //   -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set
  //   -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 4 -j DROP
  // The first line WRITES the per-source kernel list (--set, matches
  // unconditionally — pure bookkeeping); the second READS it (--update /
  // --rcheck / --remove) and is where the protection actually happens. Copy
  // only the writer and the list fills forever while nothing consults it —
  // the port keeps accepting at full line speed while the ruleset reads like
  // it throttles. Copy only the reader and it consults a list nothing ever
  // fills — the plain check is constant-false (the DROP that looks like
  // brute-force protection can never match), and a NEGATED check
  // (`! --rcheck`) is constant-TRUE, silently unconditional. Both halves
  // load without a word. Same state-written-that-nothing-reads family as
  // notrack-one-way. Lists are keyed kernel-wide by --name (default
  // "DEFAULT"), so pairing is judged across every table and chain in the
  // paste. iptables/ip6tables only: nft's equivalent (a dynamic set / meter)
  // declares the state and its use in one statement and cannot be split, and
  // ufw's `limit` verb compiles both halves itself.
  function detectRecentOneWay(result, findings) {
    if (result.format !== 'iptables' && result.format !== 'ip6tables') return;
    const byName = new Map(); // list name -> { writers: [entry], readers: [entry] }
    for (const table of result.tables) {
      for (const chain of table.chains) {
        chain.rules.forEach((rule, idx) => {
          const raw = String(rule.raw || '');
          if (!/-m\s+recent\b/.test(raw)) return;
          const nameM = raw.match(/--name\s+(\S+)/);
          const name = nameM ? nameM[1] : 'DEFAULT';
          const group = byName.get(name) || { writers: [], readers: [] };
          const opM = raw.match(/--(rcheck|update|remove)\b/);
          if (/--set\b/.test(raw)) group.writers.push({ table, chain, rule, idx });
          if (opM) {
            group.readers.push({
              table, chain, rule, idx,
              op: opM[1],
              negated: new RegExp(`!\\s+--${opM[1]}\\b`).test(raw),
            });
          }
          byName.set(name, group);
        });
      }
    }
    for (const [name, { writers, readers }] of byName) {
      if (writers.length && !readers.length) {
        for (const w of writers) {
          findings.push({
            id: 'recent-one-way',
            severity: 'warning',
            table: w.table.name,
            tableFamily: w.table.family || null,
            chain: w.chain.name,
            ruleIdx: w.idx,
            title: `-m recent --set fills list "${name}" that nothing ever consults — the limiter it was meant to feed never fires`,
            details: `\`--set\` is the bookkeeping half of the \`-m recent\` recipe: it records the source address in kernel list \`${name}\` (/proc/net/xt_recent/${name}) and matches unconditionally — the protection lives in a second rule that READS the list and acts on it, and no rule in this paste does (\`--update\`, \`--rcheck\` or \`--remove\` on the same \`--name\`). The list fills forever while the traffic it was deployed to throttle keeps arriving at full speed; nothing errors, and the ruleset reads like it limits. Add the reader half, above the ACCEPT: \`-m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 4 --name ${name} -j DROP\` with the same protocol/port match as this rule.`
          });
        }
      } else if (readers.length && !writers.length) {
        for (const r of readers) {
          findings.push({
            id: 'recent-one-way',
            severity: 'warning',
            table: r.table.name,
            tableFamily: r.table.family || null,
            chain: r.chain.name,
            ruleIdx: r.idx,
            title: `-m recent --${r.op} consults list "${name}" that nothing ever fills — ${r.negated ? 'the negated check matches every packet' : 'this rule can never match'}`,
            details: `\`--${r.op}\` reads kernel list \`${name}\`, but no rule in this paste ever writes to it (\`--set\` on the same \`--name\`). A check against a list that stays empty is a constant: ${r.negated ? 'this NEGATED check is constant-TRUE — the match is decoration and the rule fires for every packet, whatever the intent was' : 'constant-false — this rule never matches, and the verdict it carries (the brute-force DROP, the port-knock ACCEPT) is silently inert; every attempt sails past it'}. Add the writer half on the same traffic: \`-m conntrack --ctstate NEW -m recent --set --name ${name}\` (a rule with no \`-j\` is valid — it only does the bookkeeping).`
          });
        }
      }
    }
  }

  // ── port-match-without-protocol ─────────────────────────────────────
  // `--dport` / `--sport` (and multiport `--dports` / `--sports`) are
  // options of the tcp/udp match extensions — they don't exist until a
  // protocol pulls that extension in. Write a port match with NO `-p` and
  // the rule doesn't just misbehave, it FAILS TO PARSE, and because
  // iptables-restore is atomic the WHOLE ruleset is refused: on boot the
  // firewall never comes up (open or shut depending on the kernel's default
  // policy — neither is what the file describes). Measured with
  // `iptables-restore --test` (no root needed, v1.8.11):
  //   -A INPUT --dport 22 -j ACCEPT      -> unknown option "--dport"
  //   -A INPUT -m tcp --dport 22 ...      -> TCP match requires '-p tcp'
  //   -A INPUT -m multiport --dports ...  -> multiport needs `-p tcp', ...
  //   -A INPUT --sport 53 -j ACCEPT       -> unknown option "--sport"
  // and each aborts the load at that line. Conservative on purpose: it fires
  // ONLY when a port match is present and there is NO `-p` at all — the
  // unambiguous, measured case. A protocol that is present but wrong for
  // ports (`-p icmp --dport`) also fails, but judging every protocol name
  // risks a false positive that cries "won't load" over a rule that will,
  // so a present `-p` stays silent. An iptables-save DUMP always writes
  // `-p tcp -m tcp --dport`, so this only ever catches HAND-WRITTEN rules —
  // exactly its audience. iptables/ip6tables only: nft and ufw have their
  // own grammar where ports and protocol are expressed together.
  function detectPortMatchWithoutProtocol(result, findings) {
    if (result.format !== 'iptables' && result.format !== 'ip6tables') return;
    for (const table of result.tables) {
      for (const chain of table.chains) {
        chain.rules.forEach((rule, idx) => {
          const t = rule.tokens || {};
          if (t.protocol) return; // a protocol is present — stay silent (conservative)
          const raw = String(rule.raw || '');
          const portOpt =
            (t.dport && '--dport') ||
            (t.sport && '--sport') ||
            (/--dports\s/.test(raw) && '--dports') ||
            (/--sports\s/.test(raw) && '--sports') ||
            null;
          if (!portOpt) return;
          findings.push({
            id: 'port-match-without-protocol',
            severity: 'error',
            table: table.name,
            tableFamily: table.family || null,
            chain: chain.name,
            ruleIdx: idx,
            title: `\`${portOpt}\` with no \`-p tcp\`/\`-p udp\` — this rule will not load, and takes the whole ruleset down with it`,
            details: `\`${portOpt}\` is an option of the tcp/udp match extension, which only exists once a protocol pulls it in — with no \`-p\`, iptables refuses the rule (\`unknown option "${portOpt}"\`, or \`TCP match requires '-p tcp'\` under an explicit \`-m tcp\`; measured). And iptables-restore is ATOMIC: this one bad line makes the ENTIRE ruleset fail to load, so on boot the firewall never comes up — the box is left on the kernel's default policy, not the one in this file. Add the protocol the port belongs to: \`-p tcp ${portOpt} <port>\` (or \`-p udp\`). Only hand-written rules hit this; \`iptables-save\` always emits the \`-p tcp\` itself.`
          });
        });
      }
    }
  }

  // ── reject-type-mismatch ────────────────────────────────────────────
  // REJECT's `--reject-with` names the packet sent back, and it has to fit
  // the rule it rides on — twice over. (1) `tcp-reset` is a TCP RST: the
  // kernel refuses to install it on a rule that isn't pinned to `-p tcp`
  // (no `-p`, another protocol, or `! -p tcp`). And this one is a trap the
  // dry run cannot see: `iptables-restore --test` says nothing (the check
  // lives in the kernel's target verification, not in the parser) and the
  // REAL commit fails — measured in a NET_ADMIN container, both backends:
  //   -A INPUT -j REJECT --reject-with tcp-reset            -> COMMIT fails
  //   -A INPUT -p udp --dport 53 -j REJECT --reject-with tcp-reset -> fails
  //   -A INPUT ! -p tcp -j REJECT --reject-with tcp-reset   -> fails
  //   -A INPUT -p tcp / -p 6 ... --reject-with tcp-reset    -> loads
  // and, restore being atomic, a good `-p tcp --dport 22 -j ACCEPT` above
  // the bad line went down with it. The catch-all "reject everything else
  // with a reset" at the bottom of a hand-written INPUT chain is exactly
  // this mistake, and it means the firewall never comes up at boot.
  // (2) The ICMP reject types are per family: iptables knows the `icmp-*`
  // names, ip6tables the `icmp6-*` ones (plus short aliases) — cross them
  // and the PARSER refuses (`unknown reject type "icmp6-port-unreachable"`
  // under iptables, `unknown reject type "icmp-port-unreachable"` under
  // ip6tables; measured, rc 2), so a typo'd name fails the same way.
  // nft has the same two edges with its own grammar, measured with `nft -c`:
  // `udp dport 53 reject with tcp reset` / `ip protocol udp reject with tcp
  // reset` -> "you cannot use tcp reset with this protocol"; `reject with
  // icmpv6 type …` inside `table ip` (or `icmp type` inside `table ip6`)
  // -> "conflicting protocols specified: ip vs ip6"; and nft -f is atomic
  // too. Two nft forms are FINE and stay silent: a bare `reject with tcp
  // reset` with no transport match (nft adds the `meta l4proto tcp`
  // dependency itself — the rule simply only ever sees TCP), and `icmp type`
  // / `icmpv6 type` inside `table inet` (accepted; `icmpx` is the
  // family-neutral spelling). Reject types nobody named (a bare `-j REJECT`)
  // default to port-unreachable and are always valid.
  const REJECT_TYPES_V4 = new Set([
    'icmp-net-unreachable', 'icmp-host-unreachable', 'icmp-port-unreachable',
    'icmp-proto-unreachable', 'icmp-net-prohibited', 'icmp-host-prohibited',
    'icmp-admin-prohibited', 'tcp-reset', 'tcp-rst'
  ]);
  const REJECT_TYPES_V6 = new Set([
    'icmp6-no-route', 'no-route', 'icmp6-adm-prohibited', 'adm-prohibited',
    'icmp6-addr-unreachable', 'addr-unreach', 'icmp6-port-unreachable',
    'port-unreach', 'icmp6-policy-fail', 'policy-fail', 'icmp6-reject-route',
    'reject-route', 'tcp-reset', 'tcp-rst'
  ]);
  const TCP_PROTOCOL_NAMES = new Set(['tcp', '6']);

  function detectRejectTypeMismatch(result, findings) {
    const format = result.format;
    const isIpt = format === 'iptables' || format === 'ip6tables';
    if (!isIpt && format !== 'nftables') return;
    for (const table of result.tables) {
      for (const chain of table.chains) {
        chain.rules.forEach((rule, idx) => {
          if (rule.action !== 'REJECT') return;
          const detail = String(rule.actionDetail || '').trim().toLowerCase();
          if (!detail) return;
          const where = {
            table: table.name,
            tableFamily: table.family || null,
            chain: chain.name,
            ruleIdx: idx
          };
          const t = rule.tokens || {};

          if (isIpt) {
            const m = detail.match(/--reject-with\s+(\S+)/);
            if (!m) return;
            const type = m[1];
            if (type === 'tcp-reset' || type === 'tcp-rst') {
              const proto = t.protocol ? String(t.protocol).toLowerCase() : null;
              const negated = /(?:^|\s)!\s+-p\s/.test(String(rule.match || ''));
              if (proto && !negated && TCP_PROTOCOL_NAMES.has(proto)) return;
              const why = !proto
                ? 'no `-p` at all — it matches every protocol'
                : negated ? '`! -p tcp` — it matches everything BUT tcp' : `\`-p ${proto}\``;
              findings.push({
                id: 'reject-type-mismatch',
                severity: 'error',
                ...where,
                title: `\`--reject-with tcp-reset\` on a rule not pinned to \`-p tcp\` (${why}) — the kernel refuses it at load, and the whole ruleset with it`,
                details: `A TCP reset can only answer TCP, so the REJECT target's kernel-side check demands \`-p tcp\` on the rule — and this rule has ${why}. The trap: \`iptables-restore --test\` passes (the check is not in the parser) and the REAL commit fails (measured: both the legacy and the nf_tables backends refuse it, \`! -p tcp\` included). Restore is ATOMIC, so this one line takes the ENTIRE ruleset down: at boot the firewall never comes up and the box sits on the kernel's default policy. Either pin the rule to TCP (\`-p tcp -j REJECT --reject-with tcp-reset\`, with a separate \`-j REJECT\` for the rest) or drop the type and let the default \`icmp-port-unreachable\` answer everything.`
              });
              return;
            }
            const valid = format === 'iptables' ? REJECT_TYPES_V4 : REJECT_TYPES_V6;
            if (valid.has(type)) return;
            const other = format === 'iptables' ? REJECT_TYPES_V6 : REJECT_TYPES_V4;
            const otherTool = format === 'iptables' ? 'ip6tables' : 'iptables';
            const crossed = other.has(type);
            findings.push({
              id: 'reject-type-mismatch',
              severity: 'error',
              ...where,
              title: `\`--reject-with ${type}\` is not a ${format} reject type${crossed ? ` (it is ${otherTool}'s)` : ''} — this rule will not parse, and takes the whole ruleset down with it`,
              details: `${format} refuses the rule at parse time (\`unknown reject type "${type}"\`, measured) — ${crossed ? `the ICMP reject types are per address family, and \`${type}\` belongs to ${otherTool}; ${format} spells its own as ${format === 'iptables' ? '`icmp-port-unreachable`, `icmp-host-unreachable`, `icmp-admin-prohibited`…' : '`icmp6-port-unreachable` (`port-unreach`), `icmp6-adm-prohibited` (`adm-prohibited`), `icmp6-no-route`…'}` : `no such reject type exists in ${format}; check the spelling against \`${format} -j REJECT --help\``}. And iptables-restore is ATOMIC: one unparsable line and the ENTIRE ruleset fails to load, so on boot the firewall never comes up. Use a type of this family — or drop \`--reject-with\` altogether: the default (port-unreachable) is valid everywhere.`
            });
            return;
          }

          // nftables
          const l4 = (t.protocol || t.l4proto) ? String(t.protocol || t.l4proto).toLowerCase() : null;
          if (/^tcp\s+reset\b/.test(detail)) {
            if (!l4 || TCP_PROTOCOL_NAMES.has(l4)) return; // bare form: nft adds the tcp dependency itself
            findings.push({
              id: 'reject-type-mismatch',
              severity: 'error',
              ...where,
              title: `\`reject with tcp reset\` on a \`${l4}\` rule — nft refuses to load it ("you cannot use tcp reset with this protocol"), and the whole file with it`,
              details: `A TCP reset can only answer TCP, and this rule pins the transport to \`${l4}\` — nft rejects the combination at load time (measured with \`nft -c\`: "you cannot use tcp reset with this protocol"), and \`nft -f\` is atomic, so the ENTIRE ruleset is refused and the firewall never comes up at boot. Match tcp (\`tcp dport …\` / \`meta l4proto tcp\`) if a reset is what you want, or use the protocol-neutral \`reject\` (port-unreachable) / \`reject with icmpx type …\`. A bare \`reject with tcp reset\` with no transport match is fine: nft adds the \`meta l4proto tcp\` dependency itself.`
            });
            return;
          }
          const fam = String(table.family || '').toLowerCase();
          const icmpv6 = /^icmpv6\s+type\b/.test(detail);
          const icmpv4 = /^icmp\s+type\b/.test(detail);
          if ((icmpv6 && fam === 'ip') || (icmpv4 && fam === 'ip6')) {
            const typeWord = icmpv6 ? 'icmpv6' : 'icmp';
            const wantWord = icmpv6 ? 'icmp' : 'icmpv6';
            findings.push({
              id: 'reject-type-mismatch',
              severity: 'error',
              ...where,
              title: `\`reject with ${typeWord} type …\` inside \`table ${fam}\` — nft refuses it ("conflicting protocols specified: ip vs ip6"), and the whole file with it`,
              details: `\`${typeWord} type\` reject types belong to the ${icmpv6 ? 'IPv6' : 'IPv4'} family, and this table is \`${fam}\` — nft rejects the file at load time (measured with \`nft -c\`: "conflicting protocols specified: ip vs ip6"), and \`nft -f\` is atomic: the ENTIRE ruleset is refused. Use \`reject with ${wantWord} type …\` in this table, \`reject with icmpx type …\` (family-neutral, valid everywhere), or a bare \`reject\`. Inside \`table inet\` either spelling is accepted (nft scopes it to the matching family).`
            });
          }
        });
      }
    }
  }

  // ── port-match-protocol-mismatch ────────────────────────────────────
  // The sibling of port-match-without-protocol for the OTHER half of the
  // mistake: a protocol IS named, and it is the wrong one for the port option
  // that follows. Measured with `iptables-restore --test` (these are PARSER
  // errors, so the dry run does see them — v1.8.11) and with `nft -c`:
  //   -A INPUT -p icmp --dport 80 -j ACCEPT         -> unknown option "--dport"
  //   -A INPUT -p esp | igmp | all | 1 --dport …     -> unknown option "--dport"
  //   -A INPUT -p udplite --dport 80                 -> unknown option (no udplite match carries ports)
  //   -A INPUT -p tcp -m udp --dport 53              -> UDP match requires '-p udp'
  //   -A INPUT -p icmp -m tcp --dport 80             -> TCP match requires '-p tcp'
  //   -A INPUT -p icmp -m multiport --dports 53,123  -> multiport only works with TCP, UDP, UDPLITE, SCTP and DCCP
  //   ip6tables -p ipv6-icmp | icmpv6 --dport 80     -> unknown option "--dport"
  //   LOADS fine: -p sctp/dccp --dport, -p 17 --dport, -p 6 --sport,
  //               -p udp -m multiport --dports, and ! -p tcp --dport 22.
  //   nft: meta l4proto udp tcp dport 22 / ip protocol udp tcp dport 22 /
  //        udp dport 53 tcp dport 22 / icmp type echo-request udp dport 53 /
  //        icmpv6 type echo-request tcp dport 22
  //          -> "conflicting transport layer protocols specified: X vs. Y"
  //        (same-protocol pairs and `meta l4proto { tcp, udp } th dport` load.)
  // Same consequence as its sibling: one unparsable line and the ATOMIC
  // restore refuses the whole ruleset, so the firewall never comes up at
  // boot. The negated form loads (measured) and stays silent, as does any
  // protocol the linter cannot read.
  const PORT_PROTOCOLS = new Set(['tcp', 'udp', 'sctp', 'dccp', '6', '17', '132', '33']);
  const MULTIPORT_PROTOCOLS = new Set([...PORT_PROTOCOLS, 'udplite', '136']);
  const MATCH_EXTENSION_PROTOCOL = {
    tcp: new Set(['tcp', '6']),
    udp: new Set(['udp', '17']),
    sctp: new Set(['sctp', '132']),
    dccp: new Set(['dccp', '33']),
    udplite: new Set(['udplite', '136'])
  };
  const NFT_TRANSPORT_PORT_RE = /(?:^|\s)(tcp|udp|sctp|dccp|udplite)\s+(?:dport|sport)\b/g;
  const NFT_PROTO_NUMBERS = { 1: 'icmp', 6: 'tcp', 17: 'udp', 33: 'dccp', 58: 'icmpv6', 132: 'sctp', 136: 'udplite' };

  function detectPortMatchProtocolMismatch(result, findings) {
    const format = result.format;
    const isIpt = format === 'iptables' || format === 'ip6tables';
    if (!isIpt && format !== 'nftables') return;
    for (const table of result.tables) {
      for (const chain of table.chains) {
        chain.rules.forEach((rule, idx) => {
          const where = {
            table: table.name,
            tableFamily: table.family || null,
            chain: chain.name,
            ruleIdx: idx
          };
          const t = rule.tokens || {};
          const match = String(rule.match || '');

          if (isIpt) {
            if (!t.protocol) return; // no -p at all: port-match-without-protocol's case
            if (/(?:^|\s)!\s+-p\s/.test(match)) return; // negated protocol loads (measured)
            const proto = String(t.protocol).toLowerCase();
            const multi = match.match(/--(dports|sports)\s/);
            const plain = (t.dport && '--dport') || (t.sport && '--sport') || null;
            if (!multi && !plain) return;
            const portOpt = multi ? `--${multi[1]}` : plain;
            const ext = match.match(/(?:^|\s)-m\s+(tcp|udp|sctp|dccp|udplite)\b/i);
            let title, details;
            if (ext && !MATCH_EXTENSION_PROTOCOL[ext[1].toLowerCase()].has(proto)) {
              const e = ext[1].toLowerCase();
              title = `\`-m ${e}\` with \`-p ${proto}\` — ${e.toUpperCase()} match requires \`-p ${e}\`, so this rule will not parse and takes the whole ruleset down with it`;
              details = `The \`${e}\` match extension only attaches to its own protocol: iptables refuses the line (\`${e.toUpperCase()} match requires '-p ${e}'\`, measured with \`iptables-restore --test\`). And iptables-restore is ATOMIC — one unparsable rule and the ENTIRE ruleset fails to load, so at boot the firewall never comes up and the box sits on the kernel's default policy. Make the two agree: \`-p ${e} -m ${e} ${portOpt} …\` (or drop the explicit \`-m\` — \`-p ${proto} ${portOpt}\` pulls the right match in by itself when ${proto} carries ports).`;
            } else if (multi && !MULTIPORT_PROTOCOLS.has(proto)) {
              title = `\`${portOpt}\` (multiport) with \`-p ${proto}\` — multiport only works with TCP, UDP, UDPLITE, SCTP and DCCP; this rule will not parse and takes the whole ruleset down with it`;
              details = `\`-m multiport\` needs a protocol that has ports, and \`${proto}\` has none: iptables refuses the line (\`multiport only works with TCP, UDP, UDPLITE, SCTP and DCCP\`, measured with \`iptables-restore --test\`). iptables-restore is ATOMIC, so the ENTIRE ruleset fails to load and the firewall never comes up at boot. Name the protocol the ports belong to (\`-p tcp\` / \`-p udp\`), or drop the port list if \`${proto}\` really is what you meant to match.`;
            } else if (!multi && !PORT_PROTOCOLS.has(proto)) {
              title = `\`${portOpt}\` with \`-p ${proto}\` — ${proto} has no ports, so this rule will not parse and takes the whole ruleset down with it`;
              details = `\`${portOpt}\` is an option of the tcp/udp/sctp/dccp match extensions, and \`-p ${proto}\` pulls none of them in: iptables refuses the line (\`unknown option "${portOpt}"\`, measured with \`iptables-restore --test\` — the same failure as a missing \`-p\`, and udplite is in this group too: no udplite match carries ports). iptables-restore is ATOMIC, so the ENTIRE ruleset fails to load and at boot the firewall never comes up. Name the protocol the port belongs to (\`-p tcp ${portOpt} …\` / \`-p udp\`), or drop the port option if \`${proto}\` is what you meant to match.`;
            } else {
              return;
            }
            findings.push({ id: 'port-match-protocol-mismatch', severity: 'error', ...where, title, details });
            return;
          }

          // nftables: two different transport protocols named in one rule,
          // reported in the order they appear (nft's own "X vs. Y" order).
          const found = [];
          let m;
          NFT_TRANSPORT_PORT_RE.lastIndex = 0;
          while ((m = NFT_TRANSPORT_PORT_RE.exec(match)) !== null) {
            found.push({ proto: m[1].toLowerCase(), at: m.index });
          }
          const l4 = match.match(/(?:ip\s+protocol|ip6\s+nexthdr|meta\s+l4proto)\s+(?!!=)(\w+)/);
          if (l4) found.push({ proto: NFT_PROTO_NUMBERS[l4[1]] || l4[1].toLowerCase(), at: l4.index });
          const ic = match.match(/(?:^|\s)(icmpv6|icmp)\s+type\b/);
          if (ic) found.push({ proto: ic[1], at: ic.index });
          found.sort((a, b) => a.at - b.at);
          const list = [];
          for (const f of found) if (!list.includes(f.proto)) list.push(f.proto);
          if (list.length < 2) return;
          findings.push({
            id: 'port-match-protocol-mismatch',
            severity: 'error',
            ...where,
            title: `\`${list[0]}\` and \`${list[1]}\` in one rule — nft refuses it ("conflicting transport layer protocols specified"), and the whole file with it`,
            details: `A rule can match ONE transport protocol; this one names ${list.map((p) => `\`${p}\``).join(' and ')} (a \`dport\`/\`sport\` match, \`meta l4proto\`, \`ip protocol\` or an \`icmp type\` all pin it). nft rejects the file at load time (measured with \`nft -c\`: "conflicting transport layer protocols specified: ${list[0]} vs. ${list[1]}"), and \`nft -f\` is atomic, so the ENTIRE ruleset is refused and the firewall never comes up at boot. Split it into one rule per protocol, or match several at once with a set: \`meta l4proto { tcp, udp } th dport 53\`.`
          });
        });
      }
    }
  }

  // ── nat-state-match-dead ─────────────────────────────────────────────
  // The nat table sees ONE packet per connection: the first one, the one
  // conntrack has just classified NEW. Every later packet of that flow
  // follows the mapping already recorded and never traverses nat again. So
  // a nat rule matching a conntrack state other than NEW can never match —
  // ESTABLISHED, RELATED, INVALID and UNTRACKED packets do not reach it.
  // MEASURED in a NET_ADMIN container (iptables 1.8.11): a nat OUTPUT chain
  // with four rules on the same port — `--ctstate NEW`, `--ctstate
  // ESTABLISHED,RELATED`, `--ctstate INVALID`, unconditional — after three
  // curl connections counted 3 / 0 / 0 / 0 packets, while the identical pair
  // in the filter table counted 3 NEW and 10 ESTABLISHED. iptables accepts
  // the rule without a word; nft accepts `ct state established` in a `type
  // nat` chain the same way. The usual shape is a copy-paste from a filter
  // chain — the "allow replies" line that belongs in filter, or a DNAT
  // meant to exempt existing connections, which exempts nothing. A state
  // set that INCLUDES new (`NEW,ESTABLISHED`) still matches (on NEW) and is
  // left alone; only a set without NEW is dead. ufw has no nat rules to
  // show and is exempt by construction.
  function detectNatStateMatchDead(result, findings) {
    const format = result.format;
    if (format === 'ufw') return;
    for (const table of result.tables) {
      for (const chain of table.chains) {
        const inNat = format === 'nftables'
          ? String(chain.type || '').toLowerCase() === 'nat'
          : String(table.name || '').toLowerCase() === 'nat';
        if (!inNat) continue; // `return` here skipped the nat table whenever filter came first (measured: 0 findings on a filter-first dump)
        chain.rules.forEach((rule, idx) => {
          const t = rule.tokens || {};
          const raw = String(t.ctstate || t.state || '');
          if (!raw) return;
          if (/(^|\s)!\s+(--ctstate|--state|ct\s+state)/.test(String(rule.match || ''))) return; // negated: leave alone
          const states = raw.toLowerCase().split(/[,\s]+/).filter(Boolean);
          if (!states.length || states.includes('new')) return;
          const spelled = format === 'nftables' ? `ct state ${raw}` : (t.ctstate ? `--ctstate ${raw}` : `--state ${raw}`);
          findings.push({
            id: 'nat-state-match-dead',
            severity: 'warning',
            table: table.name,
            tableFamily: table.family || null,
            chain: chain.name,
            ruleIdx: idx,
            title: `\`${spelled}\` in the nat table can never match — nat sees only the first (NEW) packet of a connection, so this rule is dead`,
            details: `The nat table is consulted ONCE per connection, for the packet conntrack has just classified NEW; every later packet follows the recorded mapping and never traverses nat again. A nat rule matching ${states.map((x) => x.toUpperCase()).join('/')} therefore matches nothing (measured: 3 connections counted 3 packets on the NEW rule and 0 on the ESTABLISHED,RELATED / INVALID rules in the same nat chain, against 3 / 10 for the same pair in filter). Whatever this rule was meant to do — allow replies, exempt existing connections from a DNAT, drop invalid packets — is not happening, and neither iptables nor nft complains. Move it to the filter table (where ESTABLISHED,RELATED and INVALID mean something), or drop the state match here: in nat, every packet that arrives is NEW by definition.`
          });
        });
      }
    }
  }
  // ── tcp-flags-never-match ────────────────────────────────────────────
  // The kernel evaluates a tcp-flags match as (packet flags AND mask) ==
  // comp. A flag named in comp but absent from the mask is cleared by the
  // AND before the comparison, so equality can never hold: the rule is
  // dead. MEASURED in a NET_ADMIN container (iptables 1.8.11, nft 1.1.3):
  // every form loads with rc 0 — `--tcp-flags SYN FIN`, `--tcp-flags
  // SYN,ACK FIN,SYN`, even `--tcp-flags NONE SYN` — and over three TCP
  // connections the two dead rules counted 0 packets. The negated form is
  // the mirror image and worse: an impossible test negated is ALWAYS true,
  // so `! --tcp-flags SYN FIN` matched all 12 packets and shadowed the
  // correct `--tcp-flags FIN,SYN,RST,ACK SYN` rule and the unconditional
  // one after it (both at 0). nft accepts `tcp flags & syn == fin` the same
  // way. The usual shape is an anti-scan block copied from a blog with the
  // mask narrowed by hand. Correct shapes — comp inside the mask, `ALL
  // NONE`, `--syn` (printed as `FIN,SYN,RST,ACK SYN`) — are left alone, as
  // is anything whose flag spelling we cannot read (conservative). ufw
  // shows no flag matches.
  const TCP_FLAG_BITS = { fin: 1, syn: 2, rst: 4, psh: 8, ack: 16, urg: 32, ecn: 64, ece: 64, cwr: 128 };
  function tcpFlagBits(spec) {
    const s = String(spec || '').trim().replace(/^\(|\)$/g, '').trim();
    if (!s) return null;
    if (/^0x[0-9a-f]+$/i.test(s) || /^\d+$/.test(s)) return { bits: Number(s) };
    let bits = 0;
    for (const p of s.toLowerCase().split(/[,|\s]+/).filter(Boolean)) {
      if (p === 'all') bits |= 0x3f;
      else if (p === 'none') continue;
      else if (p in TCP_FLAG_BITS) bits |= TCP_FLAG_BITS[p];
      else return null;
    }
    return { bits };
  }
  function tcpFlagNames(bits) {
    const out = [];
    for (const [n, b] of Object.entries(TCP_FLAG_BITS)) if ((bits & b) && n !== 'ece') out.push(n.toUpperCase());
    return out;
  }
  function detectTcpFlagsNeverMatch(result, findings) {
    const format = result.format;
    if (format === 'ufw') return;
    for (const table of result.tables) {
      for (const chain of table.chains) {
        chain.rules.forEach((rule, idx) => {
          const t = rule.tokens || {};
          if (t.tcp_flags_mask === undefined) return;
          const mask = tcpFlagBits(t.tcp_flags_mask);
          const comp = tcpFlagBits(t.tcp_flags_comp);
          if (!mask || !comp) return;
          const outside = comp.bits & ~mask.bits;
          if (!outside) return;
          const names = tcpFlagNames(outside).join('/');
          const spelled = format === 'nftables'
            ? `tcp flags & ${t.tcp_flags_mask} ${t.tcp_flags_negated ? '!=' : '=='} ${t.tcp_flags_comp}`
            : `${t.tcp_flags_negated ? '! ' : ''}--tcp-flags ${t.tcp_flags_mask} ${t.tcp_flags_comp}`;
          const title = t.tcp_flags_negated
            ? `\`${spelled}\` matches EVERY TCP packet — ${names} is tested but not in the mask, the test is impossible and its negation is always true: the flag check is a no-op`
            : `\`${spelled}\` can never match — ${names} is tested but not in the mask, so (flags & mask) == comp is impossible: this rule is dead`;
          findings.push({
            id: 'tcp-flags-never-match',
            severity: 'error',
            table: table.name,
            tableFamily: table.family || null,
            chain: chain.name,
            ruleIdx: idx,
            title,
            details: `The kernel evaluates a tcp-flags match as (packet flags AND mask) == comp. ${names} is named in comp but absent from the mask, so the AND clears it before the comparison and equality can never hold. Measured (iptables 1.8.11 / nft 1.1.3): every such rule loads with rc 0 — \`--tcp-flags SYN FIN\` and \`--tcp-flags SYN,ACK FIN,SYN\` counted 0 packets over three TCP connections, while the negated \`! --tcp-flags SYN FIN\` took all 12 and shadowed every rule after it. ${t.tcp_flags_negated ? 'Negated, this rule applies to every TCP packet that reaches it — a DROP here blackholes TCP, an ACCEPT lets everything through.' : 'If this rule was meant as a guard (an anti-scan DROP, say), that guard does not exist.'} Put the tested flags in the mask — \`--tcp-flags ${format === 'nftables' ? '' : ''}SYN,FIN FIN\` tests FIN with SYN clear — or use the canonical scan patterns (\`--tcp-flags ALL FIN,SYN\`, \`--tcp-flags ALL NONE\`, \`--syn\`).`
          });
        });
      }
    }
  }
  // ── tcp-option-without-tcp ───────────────────────────────────────────
  // `--syn`, `--tcp-flags` and `--tcp-option` are options of the tcp match
  // extension, which only exists once `-p tcp` pulls it in. Under another
  // protocol, or with no `-p` at all, iptables does not have the option:
  // MEASURED (iptables 1.8.11): `-p udp --syn`, `-p icmp --syn`, a bare
  // `--syn`, `-p udp --tcp-flags SYN SYN` and `-p udp --tcp-option 8` all die
  // with `unknown option "--syn"` (rc 2) — and iptables-restore stops at that
  // line and loads NOTHING ("Error occurred at line: 4", 0 rules present).
  // The negated `! -p tcp --syn` loads (measured) and is left alone, as is a
  // protocol the linter cannot read. nft has the same wall for `tcp flags`:
  // `udp dport 53 tcp flags syn`, `meta l4proto udp tcp flags syn` and `ip
  // protocol udp tcp flags syn` are refused with "conflicting transport layer
  // protocols specified: udp vs. tcp" (nft -c rc 1, the whole file). nft
  // ACCEPTS `udp dport 53 tcp option maxseg exists` (measured), so only `tcp
  // flags` is judged there. Rules whose only tcp-ness is `-m tcp` with a port
  // option belong to port-match-protocol-mismatch and are not repeated here.
  const TCP_ONLY_OPTION_RE = /(?:^|\s)(--syn|--tcp-flags|--tcp-option)(?=\s|$)/;
  const NFT_NON_TCP_TRANSPORT_RE = /(?:^|\s)(?:(udp|sctp|dccp|udplite)\s+(?:dport|sport)\b|(?:meta\s+l4proto|ip\s+protocol|ip6\s+nexthdr)\s+(?!!=)(udp|sctp|dccp|udplite|icmp|icmpv6|ipv6-icmp|17|132|33|136|1|58)\b|(icmp|icmpv6)\s+type\b)/;
  function detectTcpOptionWithoutTcp(result, findings) {
    const format = result.format;
    const isIpt = format === 'iptables' || format === 'ip6tables';
    if (!isIpt && format !== 'nftables') return;
    for (const table of result.tables) {
      for (const chain of table.chains) {
        chain.rules.forEach((rule, idx) => {
          const match = String(rule.match || '');
          const t = rule.tokens || {};
          const where = { table: table.name, tableFamily: table.family || null, chain: chain.name, ruleIdx: idx };
          if (isIpt) {
            const opt = match.match(TCP_ONLY_OPTION_RE);
            if (!opt) return;
            if (/(?:^|\s)!\s+-p\s/.test(match)) return; // negated protocol loads (measured)
            const proto = t.protocol ? String(t.protocol).toLowerCase() : null;
            if (proto === 'tcp' || proto === '6') return;
            const spelledProto = proto ? `-p ${proto}` : 'no -p at all';
            findings.push({
              id: 'tcp-option-without-tcp',
              severity: 'error',
              ...where,
              title: `\`${opt[1]}\` with ${spelledProto} — a TCP-only option, so this rule will not parse and takes the whole ruleset down with it`,
              details: `\`${opt[1]}\` belongs to the tcp match extension, which only exists once \`-p tcp\` pulls it in. Measured (iptables 1.8.11): \`-p udp --syn\`, \`-p icmp --syn\`, a bare \`--syn\`, \`-p udp --tcp-flags SYN SYN\` and \`-p udp --tcp-option 8\` all fail with \`unknown option "${opt[1]}"\` (rc 2), and iptables-restore stops at that line and loads NOTHING — the boot ends with no firewall at all. ${proto ? `${proto.toUpperCase()} has no SYN flag to test; if the rule is about TCP, change the protocol; if it is about ${proto}, drop the option.` : 'Add `-p tcp` (the option makes no sense for any other protocol).'}`
            });
            return;
          }
          // nftables: `tcp flags` alongside a non-tcp transport is refused
          // ("conflicting transport layer protocols"); `tcp option` is not.
          if (!/(?:^|\s)tcp\s+flags\b/.test(match)) return;
          const other = match.match(NFT_NON_TCP_TRANSPORT_RE);
          if (!other) return;
          const named = other[1] || other[2] || other[3];
          findings.push({
            id: 'tcp-option-without-tcp',
            severity: 'error',
            ...where,
            title: `\`tcp flags\` next to a ${named} transport match — nft refuses the rule ("conflicting transport layer protocols specified: ${named} vs. tcp") and the whole file with it`,
            details: `A rule can name one transport protocol; \`tcp flags\` pins it to TCP and the ${named} match pins it elsewhere. Measured (nft 1.1.3): \`udp dport 53 tcp flags syn\`, \`meta l4proto udp tcp flags syn\` and \`ip protocol udp tcp flags syn\` are all refused at \`nft -c\` with "conflicting transport layer protocols specified" — nothing loads. Decide which protocol the rule is about and drop the other half.`
          });
        });
      }
    }
  }
  // ── icmp-match-without-icmp ──────────────────────────────────────────
  // The ICMP sibling of tcp-option-without-tcp: `--icmp-type` (iptables) and
  // `--icmpv6-type` (ip6tables) belong to the icmp / icmp6 match, which only
  // exists under `-p icmp` / `-p ipv6-icmp`. Under any other protocol, or no
  // `-p`, iptables refuses the line and iptables-restore loads NOTHING.
  // MEASURED (iptables 1.8.11): `-p tcp --icmp-type echo-request` and
  // `-p udp --icmp-type echo-request` die with `unknown option "--icmp-type"`
  // (rc 2); `-p tcp -m icmp --icmp-type 8` dies with `Invalid argument`
  // (rc 1). `-p icmp --icmp-type echo-request` loads. nft has the same wall:
  // `tcp dport 22 icmp type echo-request` and `meta l4proto tcp icmp type
  // echo-request` are refused at `nft -c` with "conflicting transport layer
  // protocols specified: tcp vs. icmp"; a lone `icmp type echo-request`
  // loads. The negated `! -p icmp` form and unreadable protocols are left
  // alone (the tcp-option-without-tcp trade).
  const ICMP_OPT_RE = /(?:^|\s)(--icmp-type|--icmpv6-type)(?=\s|$)/;
  const ICMP_PROTO = { '--icmp-type': new Set(['icmp', '1']), '--icmpv6-type': new Set(['ipv6-icmp', 'icmpv6', '58']) };
  const NFT_NON_ICMP_TRANSPORT_RE = /(?:^|\s)(?:(tcp|udp|sctp|dccp|udplite)\s+(?:dport|sport)\b|(?:meta\s+l4proto|ip\s+protocol|ip6\s+nexthdr)\s+(?!!=)(tcp|udp|sctp|dccp|udplite|6|17|132|33|136)\b)/;
  function detectIcmpMatchWithoutIcmp(result, findings) {
    const format = result.format;
    const isIpt = format === 'iptables' || format === 'ip6tables';
    if (!isIpt && format !== 'nftables') return;
    for (const table of result.tables) {
      for (const chain of table.chains) {
        chain.rules.forEach((rule, idx) => {
          const match = String(rule.match || '');
          const t = rule.tokens || {};
          const where = { table: table.name, tableFamily: table.family || null, chain: chain.name, ruleIdx: idx };
          if (isIpt) {
            const opt = match.match(ICMP_OPT_RE);
            if (!opt) return;
            if (/(?:^|\s)!\s+-p\s/.test(match)) return;
            const proto = t.protocol ? String(t.protocol).toLowerCase() : null;
            if (proto && ICMP_PROTO[opt[1]].has(proto)) return;
            const spelledProto = proto ? `-p ${proto}` : 'no -p at all';
            const want = opt[1] === '--icmp-type' ? '-p icmp' : '-p ipv6-icmp';
            findings.push({
              id: 'icmp-match-without-icmp',
              severity: 'error',
              ...where,
              title: `\`${opt[1]}\` with ${spelledProto} — an ICMP-only option, so this rule will not parse and takes the whole ruleset down with it`,
              details: `\`${opt[1]}\` belongs to the icmp match extension, which only exists under \`${want}\`. Measured (iptables 1.8.11): \`-p tcp --icmp-type echo-request\` dies with \`unknown option "--icmp-type"\` (rc 2) and \`-p tcp -m icmp --icmp-type 8\` with \`Invalid argument\` (rc 1); iptables-restore stops at that line and loads NOTHING — the boot ends with no firewall. ${proto ? `${proto.toUpperCase()} has no ICMP types; if the rule is about ICMP, change the protocol to ${want.slice(3)}; if it is about ${proto}, drop the option.` : `Add \`${want}\`.`}`
            });
            return;
          }
          // nftables: `icmp type` / `icmpv6 type` next to a non-icmp transport
          // is refused ("conflicting transport layer protocols").
          const nftIcmp = match.match(/(?:^|\s)(icmpv6|icmp)\s+type\b/);
          if (!nftIcmp) return;
          const other = match.match(NFT_NON_ICMP_TRANSPORT_RE);
          if (!other) return;
          const named = other[1] || other[2];
          findings.push({
            id: 'icmp-match-without-icmp',
            severity: 'error',
            ...where,
            title: `\`${nftIcmp[1]} type\` next to a ${named} transport match — nft refuses the rule ("conflicting transport layer protocols specified: ${named} vs. ${nftIcmp[1]}") and the whole file with it`,
            details: `A rule can name one transport protocol; \`${nftIcmp[1]} type\` pins it to ${nftIcmp[1]} and the ${named} match pins it elsewhere. Measured (nft 1.1.3): \`tcp dport 22 icmp type echo-request\` and \`meta l4proto tcp icmp type echo-request\` are refused at \`nft -c\` with "conflicting transport layer protocols specified". Decide which protocol the rule is about and drop the other half.`
          });
        });
      }
    }
  }




  // ── docker-user-unfiltered ─────────────────────────────────────────
  // The most famous iptables surprise of the container era: a published
  // Docker port never traverses INPUT. The packet is DNATed in the nat
  // DOCKER chain (jumped from PREROUTING) and delivered through FORWARD —
  // so every carefully-curated INPUT rule in the paste is blind to it, ufw
  // included (its user rules live in INPUT too). Appending to FORWARD is no
  // better: Docker re-inserts its own jumps at the TOP of FORWARD on every
  // restart, so admin rules sink below the accepts. The ONE chain Docker
  // creates for the operator, consults first, and guarantees never to
  // touch is DOCKER-USER — and its factory content is a single RETURN,
  // i.e. no filtering at all. Docker managing the firewall + published
  // ports + a factory DOCKER-USER = every published port reachable from
  // anywhere the host routes, whatever the rest of the ruleset says.
  //
  // Note the rest of the DNAT family cannot speak here: those detectors
  // are dispatched on nat/PREROUTING itself, and Docker's DNATs live in
  // the user chain DOCKER. This smell is the mechanism-level counterpart —
  // and the ruleset-side view of dockerscope's `port-public` (a compose
  // file publishing 5432 to 0.0.0.0 lands as exactly this DNAT).
  //
  // Three conditions, all visible in the paste, keep it honest:
  //  - the filter table shows Docker's wiring (a DOCKER-USER chain jumped
  //    from the built-in FORWARD) — without the jump nothing consults it;
  //  - DOCKER-USER is factory content: empty, or nothing but RETURN. One
  //    real rule means the operator knows the mechanism — judging their
  //    rules' quality is other smells' job;
  //  - at least one port is actually published: a DNAT rule in a chain
  //    named DOCKER. No DNAT (internal-only networks, no -p flags) means
  //    nothing is exposed and the empty chain is simply Docker's default.
  // ufw pastes are exempt by construction (ufw status never shows Docker's
  // chains — which is itself part of the trap this smell describes).
  function detectDockerUserUnfiltered(result, findings) {
    const format = result.format;
    if (format === 'ufw') return;
    const tables = result.tables || [];

    let filterTable = null;
    let dockerUser = null;
    for (const table of tables) {
      if (!isFilterTableName(table.name)) continue;
      const du = (table.chains || []).find((c) => String(c.name) === 'DOCKER-USER');
      if (!du) continue;
      const fwd = (table.chains || []).find((c) => isBuiltInForwardChain(c, format));
      if (!fwd) continue;
      const wired = (fwd.rules || []).some((r) => r.isJumpToChain && r.action === 'DOCKER-USER');
      if (!wired) continue;
      filterTable = table;
      dockerUser = du;
      break;
    }
    if (!dockerUser) return;

    const noop = (dockerUser.rules || []).every(
      (r) => String(r.action || '').toUpperCase() === 'RETURN'
    );
    if (!noop) return;

    const published = [];
    for (const table of tables) {
      for (const chain of table.chains || []) {
        if (String(chain.name) !== 'DOCKER') continue;
        for (const rule of chain.rules || []) {
          if (String(rule.action || '').toUpperCase() !== 'DNAT') continue;
          const t = rule.tokens || {};
          published.push(t.dport != null ? String(t.dport) : '?');
        }
      }
    }
    if (published.length === 0) return;

    const plural = published.length === 1 ? 'port' : 'ports';
    findings.push({
      id: 'docker-user-unfiltered',
      severity: 'warning',
      table: filterTable.name,
      tableFamily: filterTable.family || null,
      chain: dockerUser.name,
      ruleIdx: null,
      title: `Docker publishes ${plural} ${published.join(', ')} and DOCKER-USER filters nothing`,
      details: `A published container port never traverses INPUT: the packet is DNATed in the nat DOCKER chain and delivered through FORWARD, so every INPUT rule in this ruleset is blind to it (ufw's user rules included). Appending to FORWARD is no better — Docker re-inserts its own jumps at the top on every restart. The one chain Docker consults first and guarantees to leave alone is DOCKER-USER, and here it only RETURNs: the published ${plural} are reachable from anywhere the host routes. Put the restriction there, e.g. \`iptables -I DOCKER-USER -i <wan-iface> ! -s 10.0.0.0/8 -j DROP\` — and mind that the packet is already rewritten by then, so match the original published port with \`-m conntrack --ctdir ORIGINAL --ctorigdstport <port>\`, not \`--dport\`.`
    });
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
  // fully read. REDIRECT and DNAT-to-loopback (any 127/8 address, not just
  // 127.0.0.1 — 127.0.0.53 is systemd-resolved) are skipped: they don't
  // forward anywhere, the rewritten packet is delivered locally.
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
          if (cidrSubsetOrAny(rw.destination, '127.0.0.0/8')) continue; // local, not forwarded
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

  // ufw's whole UX is `ufw allow <port>` — but under `Default: allow` every
  // packet is accepted before the rule list matters, so those allows are
  // DECORATIVE: the output reads like a whitelist while restricting nothing.
  // missing-input-drop already reports the open door (error, the policy
  // axis); this reports the lie in the list (warning, the rules axis) — the
  // same silent-no-op family as dockerscope's ports-with-host-network.
  // Two exemptions keep it honest: an ALLOW with a DENY/REJECT *below* it
  // still does real work (it can punch a hole through that deny — different
  // problem, not a no-op), and LIMIT rules keep their throttle either way.
  // ufw-only on purpose: raw iptables/nft pastes can be partial rulesets,
  // and the whitelist illusion is ufw's own UX.
  // ufw lists the IPv4 rules first and the whole IPv6 block ("(v6)") after
  // them, in ONE list — but the two stacks are separate universes: a v6 rule
  // sitting "below" a v4 rule can neither save it nor shadow it. Every
  // position-based judgement over a ufw chain must partition first (measured:
  // a v4 deny added after `allow 80` sat ABOVE the v6 allows, and judging the
  // flat list called it functional when it was dead).
  function ufwFamilyPartitions(chain) {
    const v4 = [];
    const v6 = [];
    for (let i = 0; i < chain.rules.length; i++) {
      (/\(v6\)/.test(chain.rules[i].raw || '') ? v6 : v4).push(i);
    }
    return [v4, v6];
  }

  function detectAllowUnderDefaultAllow(chain, table, findings, format) {
    if (format !== 'ufw') return;
    if ((chain.policy || '').toUpperCase() !== 'ACCEPT') return;
    if (!chain.rules || chain.rules.length === 0) return;
    const noOps = [];
    for (const idxs of ufwFamilyPartitions(chain)) {
      let lastDeny = -1;
      for (let k = 0; k < idxs.length; k++) {
        const a = (chain.rules[idxs[k]].action || '').toUpperCase();
        if (a === 'DROP' || a === 'REJECT') lastDeny = k;
      }
      for (let k = lastDeny + 1; k < idxs.length; k++) {
        if ((chain.rules[idxs[k]].action || '').toUpperCase() === 'ACCEPT') noOps.push(idxs[k]);
      }
    }
    if (noOps.length === 0) return;
    noOps.sort((a, b) => a - b);
    const plural = noOps.length === 1 ? 'rule is a no-op' : 'rules are no-ops';
    findings.push({
      id: 'allow-under-default-allow',
      severity: 'warning',
      table: table.name,
      tableFamily: table.family || null,
      chain: chain.name,
      ruleIdx: noOps[0],
      title: `${noOps.length} allow ${plural} under ${chain.name}'s default-allow policy`,
      details: 'The default already accepts everything, so these allow rules restrict nothing — the list reads like a whitelist but is decorative. Set the default to deny (`ufw default deny incoming`) to make the allows real, or delete them. Allows sitting above a deny rule are not flagged: those still punch holes through it. IPv4 and IPv6 are judged as the separate stacks they are.'
    });
  }

  // The mirror image: under `Default: deny (incoming)` a DENY rule with no
  // allow below it refuses what the policy already refuses — decorative, and
  // it reads like extra hardening. Three things keep their job and are spared:
  // a deny ABOVE an allow/limit (it carves an exception out of it — ufw is
  // first-match), a REJECT under a deny policy (the policy drops silently,
  // the rule answers with a reset: a different, observable refusal — and
  // vice versa under `default reject`), and a `(log)` rule (it changes what
  // you SEE even when it cannot change the verdict).
  function detectDenyUnderDefaultDeny(chain, table, findings, format) {
    if (format !== 'ufw') return;
    const policy = (chain.policy || '').toUpperCase();
    if (policy !== 'DROP' && policy !== 'REJECT') return;
    if (!chain.rules || chain.rules.length === 0) return;
    const noOps = [];
    for (const idxs of ufwFamilyPartitions(chain)) {
      let lastAllow = -1;
      for (let k = 0; k < idxs.length; k++) {
        const a = (chain.rules[idxs[k]].action || '').toUpperCase();
        if (a === 'ACCEPT' || a === 'LIMIT') lastAllow = k;
      }
      for (let k = lastAllow + 1; k < idxs.length; k++) {
        const rule = chain.rules[idxs[k]];
        const a = (rule.action || '').toUpperCase();
        if (a !== policy) continue;               // the other refusal mode is real work
        if (/\(log\)/i.test(rule.raw || '')) continue; // observability is real work
        noOps.push(idxs[k]);
      }
    }
    if (noOps.length === 0) return;
    noOps.sort((a, b) => a - b);
    const plural = noOps.length === 1 ? 'rule is a no-op' : 'rules are no-ops';
    const mode = policy === 'REJECT' ? 'reject' : 'deny';
    findings.push({
      id: 'deny-under-default-deny',
      severity: 'info',
      table: table.name,
      tableFamily: table.family || null,
      chain: chain.name,
      ruleIdx: noOps[0],
      title: `${noOps.length} ${mode} ${plural} under ${chain.name}'s default-${mode} policy`,
      details: `The default already refuses everything these rules refuse, and no allow below them needs the exception — they read like extra hardening while doing nothing. Denies above an allow are spared (they carve exceptions out of it), a REJECT under a deny policy is spared (a reset instead of a silent drop is a different refusal), and \`(log)\` rules are spared (they change what you see). IPv4 and IPv6 are judged as the separate stacks they are.`
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

  // ── icmp-pmtud-blocked ─────────────────────────────────────────────
  // The IPv4 sibling of icmpv6-blocked, scoped to the one message IPv4
  // genuinely cannot live without: ICMP type 3 (destination-unreachable,
  // whose code 4 is fragmentation-needed). TCP sends every segment with
  // DF set and relies on routers answering "too big" with that message;
  // a firewall that swallows it turns any smaller-MTU path (VPN, PPPoE,
  // tunnels) into a black hole — the handshake's small packets pass, the
  // payload's full-size ones vanish, connections just hang. Two triggers:
  // an explicit ICMP drop with no covering accept before it (the classic
  // "block ping" rule that takes PMTUD down with it), and a deny-posture
  // chain that never accepts ICMP at all. Quiet when ICMP is accepted
  // broadly / type 3 explicitly, or when a RELATED-state accept lets
  // conntrack pass the errors for tracked connections — ESTABLISHED
  // alone is not enough, ICMP errors about a connection are RELATED.
  // Skipped for ufw (before.rules accepts dest-unreach invisibly) and
  // ip6tables (the twin's job); nftables only for ip / inet families.
  function flagIcmpPmtudBlocked(chain, table, findings, format) {
    if (format === 'ufw' || format === 'ip6tables') return;
    if (format === 'nftables') {
      const fam = String(table.family || '').toLowerCase();
      if (fam !== 'ip' && fam !== 'inet') return;
    }
    const rules = chain.rules || [];
    let flaggedRule = false;
    for (let i = 0; i < rules.length; i++) {
      const rule = rules[i];
      const a = String(rule.action || '').toUpperCase();
      if (a !== 'DROP' && a !== 'REJECT') continue;
      if (!isIcmpv4Rule(rule) || !icmpSpecCoversPmtud(rule)) continue;
      if (rules.slice(0, i).some(isPmtudAcceptRule)) continue;
      flaggedRule = true;
      findings.push({
        id: 'icmp-pmtud-blocked',
        severity: 'warning',
        table: table.name,
        tableFamily: table.family || null,
        chain: chain.name,
        ruleIdx: i,
        title: 'ICMP drop swallows fragmentation-needed — PMTUD black hole',
        details: 'Blocking ping is fine; blocking all of ICMP is not. TCP relies on ICMP type 3 code 4 (fragmentation-needed) to learn the path MTU — swallow it and any smaller-MTU path (VPN, PPPoE, tunnels) black-holes: small packets pass, full-size ones vanish, connections hang. Scope the drop with `--icmp-type echo-request`, or put a `-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT` (nft: `ct state related accept`) before it.'
      });
    }
    if (flaggedRule) return;
    const hasDenyPosture =
      isDropPolicy(chain.policy) ||
      isRejectPolicy(chain.policy) ||
      hasFinalCatchAllDrop(chain);
    if (!hasDenyPosture) return;
    // A deny-posture chain that accepts nothing (a non-forwarding host's
    // empty FORWARD DROP, a loopback-only INPUT) passes no traffic whose
    // PMTUD could break — correct config, not a black hole.
    if (!chainHasRealAccept(chain, table, new Set())) return;
    if (chainAcceptsPmtud(chain, table, new Set())) return;
    findings.push({
      id: 'icmp-pmtud-blocked',
      severity: 'warning',
      table: table.name,
      tableFamily: table.family || null,
      chain: chain.name,
      ruleIdx: null,
      title: `${chain.name} default-denies but never accepts ICMP fragmentation-needed`,
      details: 'A deny posture with no ICMP accept and no RELATED-state accept swallows ICMP type 3 (destination-unreachable, incl. fragmentation-needed) — the message Path MTU Discovery depends on. Add `-p icmp --icmp-type destination-unreachable -j ACCEPT` (nft: `icmp type destination-unreachable accept`) or a `--ctstate RELATED,ESTABLISHED` accept before the deny. ESTABLISHED alone is not enough: ICMP errors arrive as RELATED.'
    });
  }

  // True if the chain — or any chain it jumps to, followed recursively within
  // the same table — has an ACCEPT that lets fragmentation-needed through.
  function chainAcceptsPmtud(chain, table, seen) {
    if (seen.has(chain.name)) return false;
    seen.add(chain.name);
    for (const rule of chain.rules || []) {
      if (isPmtudAcceptRule(rule)) return true;
      if (rule.isJumpToChain && rule.action) {
        const target = (table.chains || []).find(c => c.name === rule.action);
        if (target && chainAcceptsPmtud(target, table, seen)) return true;
      }
    }
    return false;
  }

  function isPmtudAcceptRule(rule) {
    if (!isAcceptAction(rule)) return false;
    if (isRelatedStateRule(rule)) return true;
    return isIcmpv4Rule(rule) && icmpSpecCoversPmtud(rule);
  }

  // True if the chain accepts any non-loopback traffic at all (directly or
  // via a jumped chain) — i.e. there is traffic whose PMTUD could break.
  function chainHasRealAccept(chain, table, seen) {
    if (seen.has(chain.name)) return false;
    seen.add(chain.name);
    for (const rule of chain.rules || []) {
      if (isAcceptAction(rule) && !isLoopbackRule(rule)) return true;
      if (rule.isJumpToChain && rule.action) {
        const target = (table.chains || []).find(c => c.name === rule.action);
        if (target && chainHasRealAccept(target, table, seen)) return true;
      }
    }
    return false;
  }

  function isIcmpv4Rule(rule) {
    const proto = String((rule.tokens && rule.tokens.protocol) || '').toLowerCase();
    if (proto === 'icmp') return true;
    if (proto) return false; // any other explicit protocol (incl. the v6 names) is not v4 ICMP
    // nftables spellings: `ip protocol icmp`, `meta l4proto icmp`, `icmp type ...`
    // — the lookahead keeps icmpv6 / icmp6 from matching.
    const text = `${rule.raw || ''} ${rule.match || ''}`;
    return /(?:ip\s+protocol|meta\s+l4proto)\s+icmp(?![a-z0-9-])/i.test(text) ||
           /(^|\s)icmp\s+type\b/i.test(text);
  }

  // The rule's ICMP type restriction, or null when it matches all of ICMP.
  function icmpTypeSpec(rule) {
    const text = `${rule.raw || ''} ${rule.match || ''}`;
    let m = text.match(/--icmp-type[\s=]+(\S+)/i);
    if (m) return m[1].toLowerCase();
    m = text.match(/(^|\s)icmp\s+type\s+(\{[^}]*\}|\S+)/i);
    if (m) return m[2].toLowerCase();
    return null;
  }

  // Does the rule's type restriction include type 3 / fragmentation-needed?
  // No restriction = the whole protocol = yes.
  function icmpSpecCoversPmtud(rule) {
    const spec = icmpTypeSpec(rule);
    if (spec === null) return true;
    if (/\bany\b/.test(spec)) return true;
    if (/destination-unreachable|dest-unreach|fragmentation-needed|frag-needed/.test(spec)) return true;
    return /(^|[{,\s])3(\/4)?([},\s]|$)/.test(spec);
  }

  function isRelatedStateRule(rule) {
    const raw = String(rule.raw || '');
    return /--(?:ctstate|state)[\s=]+[A-Z,_]*RELATED/i.test(raw) ||
           /ct\s+state\s+[a-z,_\s]*related/i.test(raw);
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
    // Header-content matches the 5-dimension model does not see: TCP flags
    // and options, ICMP types. MEASURED on the tcp-flags sample: without
    // this line a dead `--tcp-flags SYN,ACK ...` DROP was reported as
    // shadowing six later rules it can never match - `-p tcp -j DROP` and
    // `-p tcp --tcp-flags X Y -j DROP` are not the same packet space.
    if (/(?:^|\s)(?:--tcp-flags|--syn|--tcp-option|--icmp-type|--icmpv6-type)(?=\s|$)/.test(raw)) return true;
    if (/\b(?:tcp\s+(?:flags|option)|icmp(?:v6)?\s+type)\b/.test(raw)) return true;
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
    return isUnconditional(rule);
  }

  // An ACCEPT with no match of any kind terminates the packet's walk through
  // the table just as surely as a DROP does — so everything below it in the
  // same chain is dead code. A rule has "no match" when none of the five
  // modeled dimensions, no interface, no ct-state and no unmodeled match is
  // present (the same test isCatchAllDeny uses).
  function isUnconditional(rule) {
    const t = rule.tokens || {};
    if (t.source || t.destination || t.dport || t.sport || t.protocol) return false;
    if (t.iif || t.oif || t.in_interface || t.out_interface) return false;
    if (ctState(rule)) return false;
    if (hasUnmodeledMatch(rule)) return false;
    return true;
  }

  // ── unreachable-after-accept-all ─────────────────────────────────────
  // The mirror of rule-after-policy-drop: an unconditional `-j ACCEPT`
  // (nft `accept` with no match) mid-chain accepts every packet and ends
  // its table walk, so every rule below it in the same chain never runs.
  // The classic footgun is a broad `-A INPUT -j ACCEPT` pasted above the
  // real rules "to test", with the rate-limited ssh accept, the INVALID
  // drop or the LOG sitting dead underneath it. Composes with
  // permissive-accept on the catch-all itself (that flags "opens the box",
  // this flags "and kills everything below"); RETURN is NOT terminal (it
  // just leaves the chain, the packet keeps being judged) so it never
  // triggers this. Applies to built-in and user chains alike — an
  // unconditional accept ends the walk in both.
  function detectUnreachableAfterAcceptAll(chain, table, findings) {
    const rules = chain.rules || [];
    let acceptIdx = -1;
    for (let i = 0; i < rules.length; i++) {
      if (isAcceptAction(rules[i]) && isUnconditional(rules[i])) { acceptIdx = i; break; }
    }
    if (acceptIdx === -1 || acceptIdx >= rules.length - 1) return;
    for (let j = acceptIdx + 1; j < rules.length; j++) {
      findings.push({
        id: 'unreachable-after-accept-all',
        severity: 'warning',
        table: table.name,
        tableFamily: table.family || null,
        chain: chain.name,
        ruleIdx: j,
        title: `Dead rule — unreachable after catch-all ACCEPT at rule #${acceptIdx + 1}`,
        details: rules[j].raw || ''
      });
    }
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

  // ── log-without-prefix ─────────────────────────────────────────────
  // A LOG rule with no `--log-prefix` (iptables), `--nflog-prefix` (NFLOG)
  // or nft `log prefix "..."` writes anonymous lines into syslog: every
  // dropped-packet log looks like every other, so you can't tell an INPUT
  // drop from a FORWARD drop, grep for one chain, or route a jail's lines
  // to their own file. The prefix is the label that makes the log useful
  // after the fact — cheap to add, and the last piece of the LOG family
  // (drop-without-log demands a log exists, unlimited-log that it's rate-
  // limited, log-tcp-sequence that it doesn't leak sequence numbers, this
  // that it's identifiable). Info severity: the log works, it's just
  // harder to read. Skipped for ufw, whose backend prefixes its own logs.
  function hasLogPrefix(rule) {
    const raw = String(rule.raw || '');
    // iptables --log-prefix / NFLOG --nflog-prefix, or nft `log ... prefix`.
    return /--(?:log|nflog)-prefix[\s=]/.test(raw) ||
           /(^|\s)log\b[^\n]*\bprefix\b/.test(raw);
  }

  function detectLogWithoutPrefix(chain, table, findings, format) {
    if (format === 'ufw') return;
    const rules = chain.rules || [];
    for (let i = 0; i < rules.length; i++) {
      const rule = rules[i];
      if (!isLogRule(rule)) continue;
      if (hasLogPrefix(rule)) continue;
      findings.push({
        id: 'log-without-prefix',
        severity: 'info',
        table: table.name,
        tableFamily: table.family || null,
        chain: chain.name,
        ruleIdx: i,
        title: 'LOG rule has no prefix',
        details: 'This LOG rule writes anonymous lines to syslog — with no `--log-prefix` (nft: `log prefix "..."`) every dropped-packet entry looks alike, so you can\'t tell which chain or rule produced it, grep for one, or route it to its own file. Add a prefix, e.g. `--log-prefix "DROP-FORWARD: "` (nft: `log prefix "DROP-FORWARD: "`).'
      });
    }
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

  // ── rate-limit-not-per-source ──────────────────────────────────────
  // The follow-up question to admin-port-no-rate-limit: that smell asks
  // whether a throttle EXISTS, this one asks whether it is keyed right.
  // Plain `-m limit`, `-m hashlimit` without a srcip mode, and a bare nft
  // `limit rate` all keep ONE token bucket that every client drains
  // together — so an attacker holding the bucket empty with a trickle of
  // SYNs makes the rule drop everyone else's connections too, and the
  // "brute-force throttle" doubles as a remote off-switch for the service
  // (the classic flaw of the tutorial SYN-flood recipe). Per-source
  // limiters keep a bucket per client: `-m hashlimit --hashlimit-mode
  // srcip`, `-m recent`, `-m connlimit` (nft: a meter / dynamic set keyed
  // on `ip saddr`, or `ct count`). Scoped to TCP on purpose — a global
  // cap is the right tool where TOTAL volume is the concern, and our own
  // smells prescribe exactly that for ICMP echo (unlimited-icmp-echo) and
  // it is a legitimate amplification ceiling for UDP services. Mutually
  // exclusive with admin-port-no-rate-limit by construction: that one
  // fires when no throttle exists, this one when the throttle is shared.
  // Skipped for ufw: its `limit` verb compiles to a per-source `-m recent`
  // pair in the backend, and `ufw status` cannot express raw matches.
  function isTcpRule(rule) {
    const proto = String((rule.tokens && rule.tokens.protocol) || '').toLowerCase();
    if (proto) return proto === 'tcp';
    const text = `${rule.raw || ''} ${rule.match || ''}`;
    return /(^|\s)-p\s+tcp\b/.test(text) ||
           /(^|\s)tcp\s+(dport|sport|flags)\b/.test(text) ||
           /\bmeta\s+l4proto\s+tcp\b/.test(text) ||
           /\bip6?\s+(protocol|nexthdr)\s+tcp\b/.test(text);
  }

  // Returns a human-readable name for the shared-bucket limiter on the
  // rule, or null when the rule has no limiter / a per-source one.
  function sharedBucketLimit(rule) {
    const raw = String(rule.raw || '');
    if (/-m\s+limit\b/.test(raw)) return '`-m limit`';
    if (/-m\s+hashlimit\b/.test(raw)) {
      const mode = raw.match(/--hashlimit-mode[\s=]+(\S+)/);
      if (mode && mode[1].split(',').includes('srcip')) return null;
      return mode ? `\`-m hashlimit --hashlimit-mode ${mode[1]}\``
                  : '`-m hashlimit` with no `--hashlimit-mode`';
    }
    // nft: a bare `limit rate` is one bucket; inside braces it is a meter /
    // dynamic-set element, keyed per entry (`{ ip saddr limit rate … }`).
    if (/\blimit\s+rate\b/.test(raw) && !/\{[^}]*\blimit\s+rate\b[^}]*\}/.test(raw)) {
      return '`limit rate`';
    }
    return null;
  }

  function detectRateLimitNotPerSource(chain, table, findings, format) {
    if (format === 'ufw') return;
    const rules = chain.rules || [];
    for (let i = 0; i < rules.length; i++) {
      const rule = rules[i];
      const action = String(rule.action || '').toUpperCase();
      const isDrop = action === 'DROP' || action === 'REJECT';
      if (!isDrop && !isAcceptAction(rule)) continue;
      if (!isTcpRule(rule)) continue;
      // An under-limit matcher on a DROP is a different bug entirely — the
      // bucket points the wrong way (rate-limit-drop-inverted's job) — and
      // on a REJECT it is the legitimate reflector-avoidance pattern (cap
      // the TOTAL cost of sending rejections; the excess falls through to
      // a silent drop), where a global bucket is exactly right. Only a
      // drop-the-excess rule is judged for bucket sharing here.
      if (isDrop && underLimitMatch(rule)) continue;
      // Same courtesy in the other direction: an over-limit matcher on an
      // ACCEPT admits only the excess — inverted regardless of how the
      // bucket is keyed (rate-limit-accept-inverted's job). Judging it for
      // bucket sharing would prescribe `--hashlimit-mode srcip` as the fix
      // for a rule whose real problem is the verdict.
      if (!isDrop && overLimitMatch(rule)) continue;
      const how = sharedBucketLimit(rule);
      if (!how) continue;
      const details = isDrop
        ? `This ${action} discards the excess over ${how}: ONE bucket whose rate is summed across every client. An attacker supplying the volume keeps the aggregate above the limit, which pushes legitimate packets into the excess and drops them alongside the flood — the flood protection doubles as a remote off-switch for the service. Key the bucket per client instead: \`-m hashlimit --hashlimit-above … --hashlimit-mode srcip\` (nft: a meter — \`meter flood { ip saddr limit rate over 25/second } drop\`) or \`-m connlimit\`. A global excess-drop belongs where total volume is the concern (ICMP echo, UDP amplification ceilings), not on a TCP service.`
        : `This ACCEPT is throttled with ${how}: a single token bucket that every client drains together. An attacker keeping it empty with a trickle of packets makes the rule drop everyone else's connections too — the brute-force throttle doubles as a remote off-switch for the service. Key the limit per client instead: \`-m hashlimit --hashlimit-mode srcip\`, \`-m recent --update --seconds 60 --hitcount 4\`, or \`-m connlimit\` (nft: a meter — \`meter ssh { ip saddr limit rate 3/minute }\` — or \`ct count\`). Global caps belong where total volume is the concern (ICMP echo, UDP amplification ceilings), not on a TCP service.`;
      findings.push({
        id: 'rate-limit-not-per-source',
        severity: 'warning',
        table: table.name,
        tableFamily: table.family || null,
        chain: chain.name,
        ruleIdx: i,
        title: 'Throttle is one shared bucket for all sources',
        details
      });
    }
  }

  // ── rate-limit-drop-inverted ───────────────────────────────────────
  // The DROP side of the rate-limit story, part one: the bucket points
  // the wrong way. `-m limit` (always), `-m hashlimit` without
  // `--hashlimit-above`, and nft `limit rate` without `over` all match
  // traffic while it is UNDER the rate — the right direction for an
  // ACCEPT ("let this much through"), exactly backwards on a DROP: the
  // rule discards the first packets of every interval (calm, legitimate
  // traffic) and once the bucket runs dry the flood sails past it to the
  // rules below. The tutorial SYN-flood recipe with `-j DROP` on the
  // limit line degrades the service on a quiet day and protects nothing
  // under attack. Judged for every protocol — the inversion is wrong
  // regardless — and per-source keying does not save it (a meter
  // `{ ip saddr limit rate 3/minute } drop` just inverts per client), so
  // this probe, unlike sharedBucketLimit, does not exempt braces.
  // DROP only, on purpose: an under-limit REJECT is the classic
  // reflector-avoidance recipe — send at most N polite rejections per
  // second (each one costs a packet), let the excess fall through to a
  // silent drop — the same global-cost cap our own smells prescribe for
  // ICMP echo. A rejection cap is deliberate; a drop cap cannot be.
  // Mutually exclusive with rate-limit-not-per-source by construction:
  // under-limit direction lands here, drop-the-excess lands there.
  // Skipped for ufw, whose `limit` verb compiles to a correct recipe.
  function underLimitMatch(rule) {
    const raw = String(rule.raw || '');
    if (/-m\s+limit\b/.test(raw)) return '`-m limit`';
    if (/-m\s+hashlimit\b/.test(raw) && !/--hashlimit-above\b/.test(raw)) {
      return /--hashlimit-upto\b/.test(raw)
        ? '`-m hashlimit --hashlimit-upto`'
        : '`-m hashlimit` (whose default is `--hashlimit-upto`)';
    }
    if (/\blimit\s+rate\b/.test(raw) && !/\blimit\s+rate\s+over\b/.test(raw)) {
      return '`limit rate` without `over`';
    }
    return null;
  }

  // The opposite direction: matchers that fire on the traffic ABOVE the
  // rate. `-m limit` has no over form, so only hashlimit-above and nft's
  // `limit rate over` land here.
  function overLimitMatch(rule) {
    const raw = String(rule.raw || '');
    if (/-m\s+hashlimit\b/.test(raw) && /--hashlimit-above\b/.test(raw)) {
      return '`-m hashlimit --hashlimit-above`';
    }
    if (/\blimit\s+rate\s+over\b/.test(raw)) return '`limit rate over`';
    return null;
  }

  function detectRateLimitDropInverted(chain, table, findings, format) {
    if (format === 'ufw') return;
    const rules = chain.rules || [];
    for (let i = 0; i < rules.length; i++) {
      const rule = rules[i];
      if (String(rule.action || '').toUpperCase() !== 'DROP') continue;
      const how = underLimitMatch(rule);
      if (!how) continue;
      findings.push({
        id: 'rate-limit-drop-inverted',
        severity: 'warning',
        table: table.name,
        tableFamily: table.family || null,
        chain: chain.name,
        ruleIdx: i,
        title: 'Rate-limited DROP points the bucket the wrong way',
        details: `This DROP is gated by ${how}, which matches traffic while it is UNDER the rate — so the rule discards the first packets of every interval (calm, legitimate traffic) and once the bucket runs dry the flood sails past it to the rules below. The service degrades on a quiet day and nothing is dropped under attack. Match the excess instead — nft \`limit rate over 25/second drop\` (per source: \`meter flood { ip saddr limit rate over 25/second } drop\`), iptables \`-m hashlimit --hashlimit-above 25/sec --hashlimit-mode srcip -j DROP\` — or keep the under-limit match on an ACCEPT followed by a catch-all DROP.`
      });
    }
  }

  // ── rate-limit-accept-inverted ─────────────────────────────────────
  // The fourth quadrant of the rate-limit matrix, and the only one that
  // was still unjudged. Under-limit ACCEPT = a correct throttle (judged
  // only for bucket sharing); under-limit DROP = rate-limit-drop-inverted;
  // over-limit DROP = the correct drop-the-excess recipe (judged for
  // sharing); over-limit ACCEPT = THIS: the rule admits only the traffic
  // ABOVE the rate. Calm, legitimate traffic never matches and falls
  // through to whatever sits below — usually the default deny — so the
  // service is dead on a quiet day and springs to life only under flood.
  // Typically born of a half-fix: someone flips the tutorial recipe's
  // matcher to `over` / `--hashlimit-above` but forgets to flip the
  // verdict (or swaps verdicts while refactoring). Per-source keying does
  // not save it — a meter `{ ip saddr limit rate over 3/minute } accept`
  // just inverts per client — and the protocol doesn't matter (admitting
  // only excess ICMP is equally backwards), so like its DROP sibling this
  // judges every protocol and never exempts braces. Mutually exclusive
  // with rate-limit-not-per-source by construction: an over-limit ACCEPT
  // lands here and only here (the verdict is the bug, not the keying).
  // Skipped for ufw, whose `limit` verb compiles to a correct recipe.
  function detectRateLimitAcceptInverted(chain, table, findings, format) {
    if (format === 'ufw') return;
    const rules = chain.rules || [];
    for (let i = 0; i < rules.length; i++) {
      const rule = rules[i];
      if (!isAcceptAction(rule)) continue;
      const how = overLimitMatch(rule);
      if (!how) continue;
      findings.push({
        id: 'rate-limit-accept-inverted',
        severity: 'warning',
        table: table.name,
        tableFamily: table.family || null,
        chain: chain.name,
        ruleIdx: i,
        title: 'Rate-limited ACCEPT admits only the excess',
        details: `This ACCEPT is gated by ${how}, which matches traffic only while it is ABOVE the rate — calm, legitimate traffic never matches and falls through to the rules below (usually the default deny), so the service is dead on a quiet day and answers only under flood. Flip the direction, not the keying: accept under the limit (\`-m hashlimit --hashlimit-upto … --hashlimit-mode srcip -j ACCEPT\`, nft \`limit rate 10/second accept\`) — or keep the over-limit match but make it a DROP that sheds the excess above a plain ACCEPT.`
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

  // ── source-port-trust ──────────────────────────────────────────────
  // The source port is the cheapest field in the packet to forge: it is
  // whatever socket the sender binds, so "from port 53" costs an attacker
  // one option (nmap ships -g/--source-port precisely to walk through
  // rules like this). An inbound ACCEPT keyed on --sport with no
  // destination port is the pre-conntrack idiom for admitting replies
  // (DNS answers, active-FTP data) — and it opens every local port to
  // anyone who remembers to set their source port. Judged only on chains
  // reachable from INPUT / FORWARD (BFS over jumps, same as unused-chain):
  // on the OUTPUT side the sport is the host's OWN port and matching it is
  // how stateless egress rules are legitimately written. A rule that also
  // pins the destination port is spared (the service scopes it — the sport
  // is then decoration, not the gate), and so is an ESTABLISHED/RELATED
  // rule (conntrack is the gate). Blocking by sport stays unflagged: the
  // usual wide-caution-ok, borrowed-trust-not rule shared with
  // mac-based-trust and bogon-source-accept. Skipped for ufw (its status
  // output has no source-port match).
  function detectSourcePortTrust(table, findings, format) {
    if (format === 'ufw') return;
    const chains = table.chains || [];
    const byName = new Map(chains.map(c => [c.name, c]));
    const inbound = new Set();
    const queue = [];
    for (const chain of chains) {
      if (isBuiltInInputChain(chain, format) || isBuiltInForwardChain(chain, format)) {
        inbound.add(chain.name);
        queue.push(chain);
      }
    }
    while (queue.length) {
      const chain = queue.shift();
      for (const rule of chain.rules || []) {
        if (!rule.isJumpToChain || !rule.action) continue;
        const target = byName.get(rule.action);
        if (target && !inbound.has(target.name)) {
          inbound.add(target.name);
          queue.push(target);
        }
      }
    }
    for (const chain of chains) {
      if (!inbound.has(chain.name)) continue;
      const rules = chain.rules || [];
      for (let i = 0; i < rules.length; i++) {
        const rule = rules[i];
        if (!isAcceptAction(rule)) continue;
        const t = rule.tokens || {};
        if (!t.sport || t.dport) continue;
        if (isEstablishedOnlyRule(rule)) continue;
        findings.push({
          id: 'source-port-trust',
          severity: 'warning',
          table: table.name,
          tableFamily: table.family || null,
          chain: chain.name,
          ruleIdx: i,
          title: `Trusts a spoofable source port (sport ${t.sport})`,
          details: `The source port is whatever socket the sender binds — any client can claim port ${t.sport} (nmap's -g/--source-port exists precisely to walk through rules like this), and with no destination port pinned this accept opens every local port to whoever does. It is the pre-conntrack idiom for admitting replies; the modern spelling is \`-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\` (nft: \`ct state established,related accept\`). If a stateless match is truly required, pin the destination port and the source address too — a source port is a hint, never an identity.`
        });
      }
    }
  }

  // ── udp-amplifier-exposed ──────────────────────────────────────────
  // Every other smell here asks "who gets INTO this host?". This one asks
  // the opposite: who does this host ATTACK? UDP needs no handshake, so a
  // reflector answers a forged source address — the attacker sends a small
  // query claiming the victim's IP and the host mails the victim a much
  // bigger answer. That is how a home NAS becomes a DDoS weapon: the 1.35
  // Tbps GitHub flood (2018) came off open memcached, and the 400 Gbps
  // Spamhaus/OVH floods off open NTP and DNS. The cost is not "someone
  // reads your cache" (exposed-admin-port's axis, which composes here for
  // memcached) — it is your uplink saturated and your provider's abuse
  // desk on the phone about traffic you never sent.
  //
  // Ports carry their documented amplification factor (US-CERT TA14-017A
  // and the memcached / WS-Discovery advisories) so the finding states the
  // real multiplier. Deliberately limited to factors around 25x and above:
  // SNMP (6.3x), NetBIOS (3.8x) and mDNS (10x) are left out — they reflect
  // too, but a smell that fires on every LAN service earns nothing.
  //
  // Exemptions that keep it honest:
  //  - a restricted source (any -s that is not "any") is spared: a resolver
  //    or NTP server for your own subnet is the normal, correct setup;
  //  - ESTABLISHED/RELATED-gated accepts are spared (those are replies to
  //    the host's own queries, not a service);
  //  - ANY rate limit is spared, per-source or global — unlike the TCP
  //    brute-force case, a TOTAL ceiling is exactly the right control for
  //    amplification (it caps what the host can emit), which is what
  //    rate-limit-not-per-source already says by scoping itself to TCP;
  //  - OUTPUT-side rules are never judged (BFS from INPUT/FORWARD, the
  //    unused-chain machinery): there the port is the host's own client
  //    socket, not a service anyone can reach;
  //  - DROP/REJECT rules obviously never fire.
  // ufw IS covered (its status prints the protocol), with one wrinkle worth
  // knowing: `ufw allow 53` with no protocol opens TCP *and* UDP, so a
  // protocol-less ufw allow counts as UDP here — that spelling is exactly
  // how an accidental open resolver usually gets created.
  const AMPLIFIER_PORTS = {
    19:    { service: 'chargen',       factor: '358x' },
    53:    { service: 'dns',           factor: 'up to 54x' },
    111:   { service: 'rpcbind',       factor: 'up to 28x' },
    123:   { service: 'ntp',           factor: '556x' },
    389:   { service: 'cldap',         factor: 'up to 70x' },
    1900:  { service: 'ssdp',          factor: '30x' },
    3702:  { service: 'ws-discovery',  factor: 'up to 500x' },
    11211: { service: 'memcached',    factor: 'up to 51,000x' }
  };

  function isUdpRule(rule, format) {
    const proto = String((rule.tokens && rule.tokens.protocol) || '').toLowerCase();
    if (proto) return proto === 'udp';
    // A ufw allow with no protocol opens both transports — UDP included.
    if (format === 'ufw') return true;
    const text = `${rule.raw || ''} ${rule.match || ''}`;
    return /(^|\s)-p\s+udp\b/.test(text) ||
           /(^|\s)udp\s+(dport|sport)\b/.test(text) ||
           /\bmeta\s+l4proto\s+udp\b/.test(text) ||
           /\bip6?\s+(protocol|nexthdr)\s+udp\b/.test(text);
  }

  function matchAmplifierPort(rule) {
    const d = rule.tokens && rule.tokens.dport;
    if (!d) return null;
    for (const portStr of Object.keys(AMPLIFIER_PORTS)) {
      const port = +portStr;
      if (portInDport(port, String(d))) {
        return Object.assign({ port }, AMPLIFIER_PORTS[portStr]);
      }
    }
    return null;
  }

  function detectUdpAmplifierExposed(table, findings, format) {
    const chains = table.chains || [];
    const byName = new Map(chains.map(c => [c.name, c]));
    const inbound = new Set();
    const queue = [];
    for (const chain of chains) {
      if (isBuiltInInputChain(chain, format) || isBuiltInForwardChain(chain, format)) {
        inbound.add(chain.name);
        queue.push(chain);
      }
    }
    while (queue.length) {
      const chain = queue.shift();
      for (const rule of chain.rules || []) {
        if (!rule.isJumpToChain || !rule.action) continue;
        const target = byName.get(rule.action);
        if (target && !inbound.has(target.name)) {
          inbound.add(target.name);
          queue.push(target);
        }
      }
    }
    for (const chain of chains) {
      if (!inbound.has(chain.name)) continue;
      const rules = chain.rules || [];
      for (let i = 0; i < rules.length; i++) {
        const rule = rules[i];
        if (!isAcceptAction(rule)) continue;
        if (!isSourceAny(rule)) continue;
        if (!isUdpRule(rule, format)) continue;
        if (isEstablishedRule(rule)) continue;
        if (isRateLimited(rule)) continue;
        const hit = matchAmplifierPort(rule);
        if (!hit) continue;
        findings.push({
          id: 'udp-amplifier-exposed',
          severity: 'warning',
          table: table.name,
          tableFamily: table.family || null,
          chain: chain.name,
          ruleIdx: i,
          title: `Open UDP reflector: ${hit.service} (port ${hit.port}, ${hit.factor} amplification) accepted from any source`,
          details: `UDP takes no handshake, so this service answers forged source addresses: an attacker sends a small ${hit.service} query claiming the victim's IP and the host mails the victim a reply ${hit.factor} the size. The damage lands on someone else — your uplink saturated, your provider's abuse desk calling about traffic you never sent (open memcached carried the 1.35 Tbps GitHub flood; open NTP and DNS carried the 400 Gbps Spamhaus/OVH ones). Restrict the source to the subnet that actually needs it (\`-s 192.168.1.0/24\`), or cap what the host can emit with a rate limit (\`-m limit --limit 10/sec\`; nft: \`limit rate 10/second\`) — either one clears this finding. If the service is not meant to be public at all, close the port: for memcached, bind it to localhost and disable UDP (\`-U 0\`).`
        });
      }
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

  // ── dnat-unscoped ──────────────────────────────────────────────────
  // A DNAT that names neither a destination address (`-d` / nft `ip daddr`)
  // nor an input interface (`-i` / nft `iifname`) matches that port on
  // EVERY packet entering the router — not just what arrives on the public
  // side. A LAN client talking to *any* host on that port is silently
  // hijacked into the forward too (and so is traffic between internal
  // segments). A port-forward should say where it applies: the public
  // address or the outside interface. REDIRECT is exempt on purpose — it
  // rewrites to the local host, and transparent-proxy REDIRECTs
  // legitimately match any destination.
  function detectDnatUnscoped(table, chain, findings) {
    const rules = chain.rules || [];
    for (let i = 0; i < rules.length; i++) {
      const rule = rules[i];
      if (String(rule.action || '').toUpperCase() !== 'DNAT') continue;
      const t = rule.tokens || {};
      if (t.destination || t.iface_in) continue;
      findings.push({
        id: 'dnat-unscoped',
        severity: 'warning',
        table: table.name,
        tableFamily: table.family || null,
        chain: chain.name,
        ruleIdx: i,
        title: 'DNAT with no destination address or input interface hijacks the port everywhere',
        details: `${rule.raw || ''} — with neither \`-d <public-ip>\` nor \`-i <wan-iface>\` (nft \`ip daddr\` / \`iifname\`) this rewrite applies to every packet entering any interface: LAN clients talking to any host on this port get forwarded too. Scope it to the public address or the outside interface.`
      });
    }
  }

  // ── dnat-to-loopback ───────────────────────────────────────────────
  // The fifth side of the DNAT family: exposed-via-dnat asks who can reach
  // the target, dnat-forward-blocked whether the forward works, dnat-unscoped
  // what else it swallows, dnat-no-hairpin whether it works from the inside —
  // this one asks where the rewrite SENDS the packet. A PREROUTING DNAT to
  // 127.0.0.1 (or any 127/8 address — 127.0.0.53 is systemd-resolved) is the
  // classic "publish the localhost-only admin panel" recipe, and it is broken
  // both ways:
  // - by default it does nothing: the kernel refuses to route a packet from
  //   the wire to a loopback address (a martian destination), so the forward
  //   is silently dark;
  // - the fix every forum thread offers — `sysctl route_localnet=1` — works
  //   by removing the kernel's own guarantee that 127/8 is unreachable from
  //   outside. Every service bound to 127.0.0.1 is then one spoofed packet
  //   away from any on-link sender: exactly the hole kube-proxy opened
  //   (CVE-2020-8558) and the hole missing-loopback-spoof-drop exists to
  //   close from the firewall side.
  // The honest fixes never touch loopback routing: bind the service on an
  // address the filter table can scope (that is what the firewall is FOR),
  // front it with a reverse proxy — or, when the service listens on the
  // router's own address, REDIRECT. REDIRECT itself is exempt on purpose:
  // its "127.0.0.1" in the trace model is shorthand, the kernel rewrites to
  // the incoming interface's address and no loopback routing is involved.
  // An `-i lo`-scoped DNAT is exempt too — traffic already on loopback
  // stays there. nat/OUTPUT rewrites are never judged (the dispatch is
  // PREROUTING-only): DNAT-ing the host's OWN traffic to 127.0.0.1 is how
  // transparent local proxies are legitimately written.
  function detectDnatToLoopback(table, chain, findings) {
    if (!window.FirewallScope || typeof window.FirewallScope.extractDnatRewrite !== 'function') return;
    const extract = window.FirewallScope.extractDnatRewrite;
    const rules = chain.rules || [];
    for (let i = 0; i < rules.length; i++) {
      const rule = rules[i];
      if (String(rule.action || '').toUpperCase() !== 'DNAT') continue;
      const t = rule.tokens || {};
      if (t.iface_in === 'lo') continue;
      const rw = extract(rule);
      const v4Loopback = !!(rw && rw.destination && cidrSubsetOrAny(rw.destination, '127.0.0.0/8'));
      // parseDnatTarget only models dotted-quad targets, so the v6 loopback
      // (`--to-destination [::1]:8080`, nft `dnat to [::1]:8080`) is read
      // from the raw rewrite target directly.
      const v6Loopback = !v4Loopback
        && /(?:--to(?:-destination)?|\bto)\s+\[?::1\]?(?::\d+)?(?:\s|$)/.test(String(rule.raw || ''));
      if (!v4Loopback && !v6Loopback) continue;
      const target = v4Loopback
        ? (rw.dport != null ? `${rw.destination}:${rw.dport}` : rw.destination)
        : '::1';
      const port = rw && rw.dport != null ? rw.dport : '<port>';
      findings.push({
        id: 'dnat-to-loopback',
        severity: 'warning',
        table: table.name,
        tableFamily: table.family || null,
        chain: chain.name,
        ruleIdx: i,
        title: `DNAT rewrites inbound traffic to loopback (${target}) — dark by default, dangerous when "fixed"`,
        details: `${rule.raw || ''} — the kernel refuses to route packets from the wire to a loopback address, so this forward silently delivers nothing; and the usual fix (\`sysctl route_localnet=1\`) removes that refusal wholesale, leaving every 127.0.0.1-bound service one spoofed packet away from any on-link sender (CVE-2020-8558). Bind the service on an address the filter table can scope, front it with a proxy — or, if it listens on the router's own address, use REDIRECT (\`-j REDIRECT --to-ports ${port}\` / nft \`redirect to :${port}\`).`
      });
    }
  }

  // ── dnat-no-hairpin ────────────────────────────────────────────────
  // The fourth side of the DNAT family: exposed-via-dnat asks who can
  // reach the target, dnat-forward-blocked whether the forward works at
  // all, dnat-unscoped what else the rewrite swallows — this one asks
  // whether it works FROM THE INSIDE. A LAN client connecting to the
  // router's public address rides the same DNAT to the internal server,
  // but the server sees the client's own on-link source and replies
  // DIRECTLY, bypassing the router — the client expected the reply from
  // the public address and drops the half-open connection. The forward
  // works from the internet and silently fails from the LAN: the classic
  // "works from my phone on 4G, not from my desk" mystery.
  //
  // The fix is the hairpin (NAT-loopback) leg: a POSTROUTING MASQUERADE /
  // SNAT scoped to the DNAT target as *destination*, so hairpinned flows
  // leave wearing the router's address and the reply returns through it.
  // Split-horizon DNS is the other legitimate fix — hence info severity.
  //
  // Never cries wolf:
  // - only when POSTROUTING already SNATs / MASQUERADEs something (the
  //   box is provably a NAT router, not a partial paste);
  // - only DNATs to RFC1918 targets (a public target doesn't hairpin)
  //   that a LAN packet can actually match — an `-i <wan>`-scoped DNAT
  //   never sees LAN traffic, so no SNAT leg could help it (that setup
  //   needs split DNS, a different conversation);
  // - suppressed by any SNAT / MASQUERADE whose destination covers the
  //   target (the hairpin leg, however else it is scoped), or by one
  //   with neither destination nor out-interface (it masquerades the
  //   hairpinned flow incidentally). An `-o <wan>`-only masquerade — the
  //   classic outbound rule — does NOT cover it: hairpinned replies
  //   leave through the LAN interface.
  const RFC1918_NETS = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'];
  function isRfc1918(ip) {
    return RFC1918_NETS.some((net) => cidrSubsetOrAny(ip, net));
  }

  function detectDnatNoHairpin(result, findings) {
    if (!window.FirewallScope || typeof window.FirewallScope.extractDnatRewrite !== 'function') return;
    const extract = window.FirewallScope.extractDnatRewrite;
    const format = result.format;
    const tables = result.tables || [];

    const snats = [];
    for (const table of tables) {
      for (const chain of table.chains || []) {
        if (!isNatPostroutingChain(table, chain, format)) continue;
        for (const rule of chain.rules || []) {
          const action = String(rule.action || '').toUpperCase();
          if (action === 'MASQUERADE' || action === 'SNAT') snats.push(rule);
        }
      }
    }
    if (snats.length === 0) return; // not provably a NAT router

    const hairpinCovered = (targetIp) => snats.some((rule) => {
      const t = rule.tokens || {};
      if (t.destination && !isAnyCidr(t.destination)) {
        return cidrSubsetOrAny(targetIp, t.destination);
      }
      return !t.iface_out;
    });

    for (const table of tables) {
      for (const chain of table.chains || []) {
        if (!isNatPreroutingChain(table, chain, format)) continue;
        const rules = chain.rules || [];
        for (let i = 0; i < rules.length; i++) {
          const rule = rules[i];
          if (String(rule.action || '').toUpperCase() !== 'DNAT') continue;
          const t = rule.tokens || {};
          if (t.iface_in) continue;
          const rw = extract(rule);
          if (!rw || !rw.destination) continue;
          if (!isRfc1918(rw.destination)) continue;
          if (hairpinCovered(rw.destination)) continue;
          const target = rw.dport != null ? `${rw.destination}:${rw.dport}` : rw.destination;
          findings.push({
            id: 'dnat-no-hairpin',
            severity: 'info',
            table: table.name,
            tableFamily: table.family || null,
            chain: chain.name,
            ruleIdx: i,
            title: `Port-forward to ${target} has no hairpin NAT — LAN clients can't use the public address`,
            details: `A LAN client connecting to the public address rides this DNAT to ${rw.destination}, but the server replies directly to the client (they share the network), bypassing the router — the client expected the reply from the public address and drops the connection. Add the hairpin leg: \`-A POSTROUTING -s <lan-subnet> -d ${rw.destination}${rw.dport != null ? ` -p tcp --dport ${rw.dport}` : ''} -j MASQUERADE\` (nft: \`ip saddr <lan-subnet> ip daddr ${rw.destination} masquerade\`) — or point LAN clients at the internal address via split-horizon DNS.`
          });
        }
      }
    }
  }

  window.FirewallScope = window.FirewallScope || {};
  window.FirewallScope.lint = lint;
})();
