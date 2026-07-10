(function () {
  'use strict';

  const SAMPLE_URLS = {
    iptables:  'samples/iptables-save.txt',
    ip6tables: 'samples/ip6tables-save.txt',
    nftables:  'samples/nft-ruleset.txt',
    ufw:       'samples/ufw-status.txt',
    leaky:     'samples/iptables-leaky.txt',
    shadowed:  'samples/iptables-shadowed.txt',
    portforward: 'samples/iptables-portforward.txt',
    exposed:   'samples/iptables-exposed-services.txt'
  };

  const FORMAT_LABELS = {
    iptables:  'iptables-save (IPv4)',
    ip6tables: 'ip6tables-save (IPv6)',
    nftables:  'nft list ruleset',
    ufw:       'ufw status verbose'
  };

  let lastResult = null;
  let lastLintReport = null;
  let lastTraceReport = null;

  document.addEventListener('DOMContentLoaded', () => {
    const textarea     = document.getElementById('ruleset-input');
    const analyzeBtn   = document.getElementById('analyze');
    const uploadBtn    = document.getElementById('upload');
    const fileInput    = document.getElementById('file-input');
    const sampleToggle = document.getElementById('load-sample');
    const sampleMenu   = document.getElementById('sample-menu');
    const formatSelect = document.getElementById('format-override');
    const formatBadge  = document.getElementById('format-badge');
    const parseError   = document.getElementById('parse-error');
    const parseWarn    = document.getElementById('parse-warnings');
    const dropOverlay  = document.getElementById('drop-overlay');
    const tabGraph     = document.getElementById('tab-graph');
    const tabTable     = document.getElementById('tab-table');
    const tabLint      = document.getElementById('tab-lint');
    const tabLintBadge = document.getElementById('lint-tab-badge');
    const tabTrace     = document.getElementById('tab-trace');
    const graphView    = document.getElementById('graph-view');
    const tableView    = document.getElementById('table-view');
    const lintView     = document.getElementById('lint-view');
    const lintContent  = document.getElementById('lint-content');
    const lintEmpty    = document.getElementById('lint-empty');
    const lintClean    = document.getElementById('lint-clean');
    const traceView    = document.getElementById('trace-view');
    const traceEmpty   = document.getElementById('trace-empty');
    const traceUI      = document.getElementById('trace-ui');
    const traceForm    = document.getElementById('trace-form');
    const traceDirection = document.getElementById('trace-direction');
    const traceProto   = document.getElementById('trace-proto');
    const traceState   = document.getElementById('trace-state');
    const traceSrc     = document.getElementById('trace-src');
    const traceSport   = document.getElementById('trace-sport');
    const traceDst     = document.getElementById('trace-dst');
    const traceDport   = document.getElementById('trace-dport');
    const traceIif     = document.getElementById('trace-iif');
    const traceOif     = document.getElementById('trace-oif');
    const traceClear   = document.getElementById('trace-clear');
    const traceResult  = document.getElementById('trace-result');
    const traceVerdict = document.getElementById('trace-verdict');
    const traceFinal   = document.getElementById('trace-final');
    const traceWarnings= document.getElementById('trace-warnings');
    const traceSteps   = document.getElementById('trace-steps');
    const graphEmpty   = document.getElementById('graph-empty');
    const tableEmpty   = document.getElementById('table-empty');
    const compareToggle = document.getElementById('compare-toggle');
    const comparePane   = document.getElementById('compare-pane');
    const compareInput  = document.getElementById('compare-input');
    const labelA        = document.getElementById('label-a');
    const diffBanner    = document.getElementById('diff-banner');
    const diffSummary   = document.getElementById('diff-summary');
    const exitDiffBtn   = document.getElementById('exit-diff');

    compareToggle.addEventListener('click', () => {
      const willOpen = comparePane.hidden;
      comparePane.hidden = !willOpen;
      labelA.hidden = !willOpen;
      compareToggle.classList.toggle('active', willOpen);
      if (willOpen) compareInput.focus();
      else compareInput.value = '';
    });

    exitDiffBtn.addEventListener('click', () => {
      comparePane.hidden = true;
      labelA.hidden = true;
      compareToggle.classList.remove('active');
      compareInput.value = '';
      diffBanner.hidden = true;
      analyze();
    });

    analyzeBtn.addEventListener('click', analyze);

    textarea.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        e.preventDefault();
        analyze();
      }
    });

    uploadBtn.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', (e) => {
      const f = e.target.files[0];
      if (f) loadFile(f);
      fileInput.value = '';
    });

    sampleToggle.addEventListener('click', () => {
      const open = sampleMenu.hidden;
      sampleMenu.hidden = !open;
      sampleToggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    });
    sampleMenu.querySelectorAll('button[data-sample]').forEach(btn => {
      btn.addEventListener('click', async () => {
        sampleMenu.hidden = true;
        sampleToggle.setAttribute('aria-expanded', 'false');
        await loadSample(btn.dataset.sample);
      });
    });
    document.addEventListener('click', (e) => {
      if (!sampleMenu.hidden && !e.target.closest('.sample-wrap')) {
        sampleMenu.hidden = true;
        sampleToggle.setAttribute('aria-expanded', 'false');
      }
    });

    let dragDepth = 0;
    window.addEventListener('dragenter', (e) => {
      e.preventDefault();
      dragDepth++;
      dropOverlay.hidden = false;
    });
    window.addEventListener('dragover', (e) => e.preventDefault());
    window.addEventListener('dragleave', () => {
      dragDepth--;
      if (dragDepth <= 0) {
        dragDepth = 0;
        dropOverlay.hidden = true;
      }
    });
    window.addEventListener('drop', (e) => {
      e.preventDefault();
      dragDepth = 0;
      dropOverlay.hidden = true;
      const f = e.dataTransfer?.files?.[0];
      if (f) loadFile(f);
    });

    tabGraph.addEventListener('click', () => switchTab('graph'));
    tabTable.addEventListener('click', () => switchTab('table'));
    tabLint .addEventListener('click', () => switchTab('lint'));
    tabTrace.addEventListener('click', () => switchTab('trace'));

    traceForm.addEventListener('submit', (e) => {
      e.preventDefault();
      runTrace();
    });
    traceClear.addEventListener('click', () => {
      traceForm.reset();
      traceDirection.value = 'input';
      traceProto.value = 'tcp';
      traceState.value = 'NEW';
      traceResult.hidden = true;
      lastTraceReport = null;
      window.FirewallScope.traceReport = null;
      // Re-render graph without highlight
      if (lastResult && !graphView.hidden) {
        window.FirewallScope.renderGraph(lastResult, lastLintReport, null);
      }
    });

    const exportWrap   = document.getElementById('export-wrap');
    const exportToggle = document.getElementById('export-toggle');
    const exportMenu   = document.getElementById('export-menu');

    exportToggle.addEventListener('click', () => {
      const open = exportMenu.hidden;
      exportMenu.hidden = !open;
      exportToggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    });
    exportMenu.querySelectorAll('button[data-format]').forEach(btn => {
      btn.addEventListener('click', () => {
        exportMenu.hidden = true;
        exportToggle.setAttribute('aria-expanded', 'false');
        window.FirewallScope.exportGraph(btn.dataset.format);
      });
    });
    document.addEventListener('click', (e) => {
      if (!exportMenu.hidden && !e.target.closest('.export-wrap')) {
        exportMenu.hidden = true;
        exportToggle.setAttribute('aria-expanded', 'false');
      }
    });

    function switchTab(which) {
      const isGraph = which === 'graph';
      const isTable = which === 'table';
      const isLint  = which === 'lint';
      const isTrace = which === 'trace';
      tabGraph.classList.toggle('active', isGraph);
      tabTable.classList.toggle('active', isTable);
      tabLint .classList.toggle('active', isLint);
      tabTrace.classList.toggle('active', isTrace);
      graphView.hidden = !isGraph;
      tableView.hidden = !isTable;
      lintView .hidden = !isLint;
      traceView.hidden = !isTrace;
      exportWrap.hidden = !isGraph;
      if (!isGraph) {
        exportMenu.hidden = true;
        exportToggle.setAttribute('aria-expanded', 'false');
      }
      if (isGraph && lastResult && window.FirewallScope.renderGraph) {
        window.FirewallScope.renderGraph(lastResult, lastLintReport, lastTraceReport);
      }
    }

    function loadFile(f) {
      const reader = new FileReader();
      reader.onload = (ev) => {
        textarea.value = ev.target.result;
        analyze();
      };
      reader.readAsText(f);
    }

    async function loadSample(key) {
      const url = SAMPLE_URLS[key];
      if (!url) return;
      try {
        const resp = await fetch(url);
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const text = await resp.text();
        textarea.value = text;
        formatSelect.value = 'auto';
        analyze();
      } catch (err) {
        showError(`Failed to load sample: ${err.message}`);
      }
    }

    function analyze() {
      const text = textarea.value;
      const textB = !comparePane.hidden ? compareInput.value : '';
      hideError();
      hideWarnings();
      diffBanner.hidden = true;

      if (!text.trim()) {
        formatBadge.hidden = true;
        graphEmpty.hidden = false;
        tableEmpty.hidden = false;
        lastResult = null;
        clearGraph();
        clearTable();
        return;
      }

      const override = formatSelect.value;
      const opts = override === 'auto' ? {} : { format: override };
      const resultA = window.FirewallScope.parse(text, opts);

      if (resultA.error) {
        showError(resultA.error);
        formatBadge.hidden = true;
        graphEmpty.hidden = false;
        tableEmpty.hidden = false;
        lastResult = null;
        clearGraph();
        clearTable();
        return;
      }

      let result = resultA;
      let isDiff = false;

      if (textB.trim()) {
        const resultB = window.FirewallScope.parse(textB, opts);
        if (resultB.error) {
          showError(`Compare side: ${resultB.error}`);
          formatBadge.hidden = true;
          graphEmpty.hidden = false;
          tableEmpty.hidden = false;
          lastResult = null;
          clearGraph();
          clearTable();
          return;
        }

        const merged = window.FirewallScope.mergeForDiff(resultA, resultB);
        if (merged.error) {
          showError(merged.error);
          formatBadge.hidden = true;
          graphEmpty.hidden = false;
          tableEmpty.hidden = false;
          lastResult = null;
          clearGraph();
          clearTable();
          return;
        }
        result = merged;
        isDiff = true;
      }

      if (isDiff) {
        const d = result.diff;
        formatBadge.innerHTML =
          `<b>${FORMAT_LABELS[result.format] || result.format}</b> · diff mode (left → right)`;
        formatBadge.hidden = false;
        diffSummary.innerHTML =
          `Diff: <span class="badge badge-added">+${d.addedRules}</span> added, ` +
          `<span class="badge badge-removed">−${d.removedRules}</span> removed, ` +
          `<span class="badge badge-moved">⇅${d.movedRules || 0}</span> moved, ` +
          `<span class="badge badge-same">=${d.sameRules}</span> unchanged · ` +
          `<span class="badge badge-added">+${d.addedChains}</span> chains, ` +
          `<span class="badge badge-removed">−${d.removedChains}</span> chains`;
        diffBanner.hidden = false;
      } else {
        const stats = countStats(result);
        formatBadge.innerHTML =
          `<b>${FORMAT_LABELS[result.format] || result.format}</b> · ${stats.tables} table${stats.tables !== 1 ? 's' : ''} · ${stats.chains} chain${stats.chains !== 1 ? 's' : ''} · ${stats.rules} rule${stats.rules !== 1 ? 's' : ''}`;
        formatBadge.hidden = false;
      }

      if (result.warnings && result.warnings.length) {
        showWarnings(result.warnings);
      }

      lastResult = result;
      graphEmpty.hidden = true;
      tableEmpty.hidden = true;

      // In diff mode the linter is skipped — a merged ruleset doesn't represent
      // a single deployable state, and pills on diff rows would clash with the
      // moved / added / removed colour-coding.
      const lintReport = isDiff
        ? { findings: [], counts: { error: 0, warning: 0, info: 0, total: 0 }, byKey: {} }
        : window.FirewallScope.lint(result);
      lastLintReport = lintReport;
      renderLintTab(lintReport, isDiff);
      window.FirewallScope.lintReport = lintReport;

      // Trace tab: a fresh analyze invalidates any previous trace.
      lastTraceReport = null;
      window.FirewallScope.traceReport = null;
      traceResult.hidden = true;
      if (isDiff) {
        traceEmpty.hidden = false;
        traceEmpty.textContent = 'Trace is disabled in diff mode. Exit the diff to trace a single ruleset.';
        traceUI.hidden = true;
      } else {
        traceEmpty.hidden = true;
        traceUI.hidden = false;
      }

      if (!graphView.hidden) {
        window.FirewallScope.renderGraph(result, lintReport, null);
      }
      window.FirewallScope.renderTable(result, lintReport);
    }

    function fillTraceForm(p) {
      traceDirection.value = p.direction || 'input';
      traceProto.value     = p.protocol  || 'tcp';
      traceSrc.value       = p.source       != null ? String(p.source)      : '';
      traceDst.value       = p.destination  != null ? String(p.destination) : '';
      traceDport.value     = p.dport        != null ? String(p.dport)       : '';
      traceSport.value     = p.sport        != null ? String(p.sport)       : '';
      traceIif.value       = p.iif || '';
      traceOif.value       = p.oif || '';
      traceState.value     = p.state || '';
    }

    function runTrace() {
      if (!lastResult) return;
      const packet = {
        direction: traceDirection.value,
        protocol: traceProto.value,
        source: traceSrc.value.trim() || undefined,
        destination: traceDst.value.trim() || undefined,
        dport: traceDport.value ? +traceDport.value : undefined,
        sport: traceSport.value ? +traceSport.value : undefined,
        iif: traceIif.value.trim() || undefined,
        oif: traceOif.value.trim() || undefined,
        state: traceState.value || undefined
      };
      const report = window.FirewallScope.trace(lastResult, packet);
      lastTraceReport = report;
      window.FirewallScope.traceReport = report;
      renderTraceResult(report, packet);
      // Re-render graph with the path highlighted so the Graph tab reflects the new trace.
      if (lastResult) {
        window.FirewallScope.renderGraph(lastResult, lastLintReport, report);
      }
    }

    function renderTraceResult(report, packet) {
      traceResult.hidden = false;
      if (report.error) {
        traceVerdict.className = 'trace-verdict v-NO_MATCH';
        traceVerdict.textContent = 'ERROR';
        traceFinal.textContent = report.error;
        traceWarnings.hidden = true;
        traceSteps.innerHTML = '';
        return;
      }
      const v = report.verdict || 'NO_MATCH';
      traceVerdict.className = 'trace-verdict v-' + v;
      traceVerdict.textContent = v;
      const pktBits = [];
      pktBits.push(`<span class="code">${escapeHtml(packet.protocol)}</span>`);
      if (packet.source)      pktBits.push(`from <span class="code">${escapeHtml(packet.source)}</span>`);
      if (packet.sport)       pktBits.push(`:<span class="code">${packet.sport}</span>`);
      if (packet.destination) pktBits.push(`to <span class="code">${escapeHtml(packet.destination)}</span>`);
      if (packet.dport)       pktBits.push(`:<span class="code">${packet.dport}</span>`);
      if (packet.iif)         pktBits.push(`iif=<span class="code">${escapeHtml(packet.iif)}</span>`);
      if (packet.oif)         pktBits.push(`oif=<span class="code">${escapeHtml(packet.oif)}</span>`);
      if (packet.state)       pktBits.push(`state=<span class="code">${escapeHtml(packet.state)}</span>`);
      const dirLabel = packet.direction === 'output' ? 'OUTPUT'
                     : packet.direction === 'forward' ? 'FORWARD'
                     : 'INPUT';
      let finalLine = `<span class="code">${dirLabel}</span> packet: ${pktBits.join(' ')}`;
      if (report.natPacket) {
        const natChain = packet.direction === 'output' ? 'nat/OUTPUT' : 'nat/PREROUTING';
        finalLine += ` &nbsp;·&nbsp; rewritten by <span class="code">${natChain}</span> → <span class="code">${escapeHtml(formatNatPair(report.natPacket))}</span>`;
      }
      if (report.finalRule) {
        const r = report.finalRule;
        finalLine += ` &nbsp;·&nbsp; decided by <span class="code">${escapeHtml(r.table)}/${escapeHtml(r.chain)}</span>`;
        finalLine += r.ruleIdx == null ? ' (chain policy)' : ` rule <span class="code">#${r.ruleIdx + 1}</span>`;
      }
      if (report.snatPacket) {
        finalLine += ` &nbsp;·&nbsp; SNAT by <span class="code">nat/POSTROUTING</span> → <span class="code">${escapeHtml(formatNatPair(report.snatPacket))}</span>`;
      }
      traceFinal.innerHTML = finalLine;

      if (report.warnings && report.warnings.length) {
        traceWarnings.hidden = false;
        traceWarnings.innerHTML = report.warnings.map(w => `<span class="w">⚠ ${escapeHtml(w)}</span>`).join('');
      } else {
        traceWarnings.hidden = true;
      }

      traceSteps.innerHTML = '';
      for (const s of report.steps) {
        const li = document.createElement('li');
        li.className = 'k-' + s.type;
        const kind = document.createElement('span'); kind.className = 'kind'; kind.textContent = s.type;
        const where = document.createElement('span'); where.className = 'where';
        if (s.table && s.chain) {
          where.textContent = `${s.table}/${s.chain}` + (s.ruleIdx != null ? ` #${s.ruleIdx + 1}` : '');
        }
        const body = document.createElement('span'); body.className = 'body';
        if (s.type === 'enter-chain') body.textContent = `entering chain ${s.chain}`;
        else if (s.type === 'match')   body.textContent = `MATCH · ${s.action} · ${shorten(s.ruleRaw)}`;
        else if (s.type === 'no-match')body.textContent = `${shorten(s.ruleRaw)}`;
        else if (s.type === 'skip')    body.textContent = `SKIP — ${s.reason} · ${shorten(s.ruleRaw)}`;
        else if (s.type === 'jump')    body.textContent = `jump → ${s.jumpedTo}`;
        else if (s.type === 'return')  body.textContent = s.reason ? `return (${s.reason})` : 'return';
        else if (s.type === 'policy')  body.textContent = `fell through → policy ${s.action}${s.reason ? ' (' + s.reason + ')' : ''}`;
        else if (s.type === 'log')     body.textContent = `${s.action} (non-terminal, continues)`;
        else if (s.type === 'dnat')    body.textContent = `DNAT · ${formatNatPair(s.before)} → ${formatNatPair(s.after)}`;
        else if (s.type === 'snat')    body.textContent = `SNAT · ${formatNatPair(s.before)} → ${formatNatPair(s.after)}`;
        else if (s.type === 'verdict') body.textContent = `final verdict: ${s.action}`;
        else                           body.textContent = JSON.stringify(s);
        li.appendChild(kind);
        li.appendChild(where);
        li.appendChild(body);
        traceSteps.appendChild(li);
      }
    }

    function shorten(s) {
      const str = String(s || '');
      return str.length > 120 ? str.slice(0, 117) + '…' : str;
    }

    function renderLintTab(report, isDiff) {
      lintContent.innerHTML = '';
      lintEmpty.hidden = true;
      lintClean.hidden = true;
      const c = report.counts;
      const total = c.total;
      tabLintBadge.hidden = total === 0;
      if (total > 0) {
        tabLintBadge.textContent = String(total);
        tabLintBadge.style.background = c.error > 0
          ? 'var(--drop)'
          : (c.warning > 0 ? 'var(--warn)' : '#3b82f6');
      }
      if (isDiff) {
        lintEmpty.hidden = false;
        lintEmpty.innerHTML = 'Linter is disabled in <b>diff mode</b>. Exit the diff to lint a single ruleset.';
        return;
      }
      if (total === 0) {
        lintClean.hidden = false;
        return;
      }

      const summary = document.createElement('div');
      summary.className = 'lint-summary';
      if (c.error)   summary.innerHTML += `<span class="pill error">${c.error} error${c.error !== 1 ? 's' : ''}</span>`;
      if (c.warning) summary.innerHTML += `<span class="pill warning">${c.warning} warning${c.warning !== 1 ? 's' : ''}</span>`;
      if (c.info)    summary.innerHTML += `<span class="pill info">${c.info} info</span>`;

      const exportGroup = document.createElement('div');
      exportGroup.className = 'lint-export';
      const btnJson = document.createElement('button');
      btnJson.type = 'button';
      btnJson.textContent = 'Export JSON';
      btnJson.addEventListener('click', () => exportLint('json', report));
      const btnMd = document.createElement('button');
      btnMd.type = 'button';
      btnMd.textContent = 'Export Markdown';
      btnMd.addEventListener('click', () => exportLint('md', report));
      exportGroup.append(btnJson, btnMd);
      summary.appendChild(exportGroup);

      lintContent.appendChild(summary);

      const list = document.createElement('div');
      list.className = 'lint-findings';
      // Sort: errors first, then warnings, then info; within severity, by table/chain/ruleIdx.
      const order = { error: 0, warning: 1, info: 2 };
      const sorted = report.findings.slice().sort((a, b) =>
        order[a.severity] - order[b.severity] ||
        (a.table || '').localeCompare(b.table || '') ||
        (a.chain || '').localeCompare(b.chain || '') ||
        ((a.ruleIdx == null ? -1 : a.ruleIdx) - (b.ruleIdx == null ? -1 : b.ruleIdx))
      );
      for (const f of sorted) {
        const row = document.createElement('div');
        row.className = `lint-finding sev-${f.severity}`;
        row.dataset.table = f.table;
        row.dataset.chain = f.chain;
        if (f.ruleIdx != null) row.dataset.ruleIdx = String(f.ruleIdx);

        const sev = document.createElement('span');
        sev.className = 'lint-finding-sev';
        sev.textContent = f.severity;
        row.appendChild(sev);

        const body = document.createElement('div');
        body.className = 'lint-finding-body';
        const title = document.createElement('div');
        title.className = 'lint-finding-title';
        title.textContent = f.title;
        body.appendChild(title);
        const loc = document.createElement('div');
        loc.className = 'lint-finding-loc';
        const codeT = `<span class="code">${escapeHtml(f.table)}${f.tableFamily ? ' [' + escapeHtml(f.tableFamily) + ']' : ''}</span>`;
        const codeC = `<span class="code">${escapeHtml(f.chain)}</span>`;
        const codeR = f.ruleIdx == null ? '' : ` · rule <span class="code">#${f.ruleIdx + 1}</span>`;
        loc.innerHTML = `${codeT} · ${codeC}${codeR} · <span class="code">${f.id}</span>`;
        body.appendChild(loc);
        if (f.details) {
          const det = document.createElement('div');
          det.className = 'lint-finding-details';
          det.textContent = f.details;
          body.appendChild(det);
        }
        row.appendChild(body);

        row.addEventListener('click', () => {
          if (f.id === 'fallthrough-accept' && f.probePacket) {
            switchTab('trace');
            fillTraceForm(f.probePacket);
            runTrace();
            return;
          }
          switchTab('table');
          // The table view is already rendered with pills; scroll to the target rule.
          window.FirewallScope.scrollToRule &&
            window.FirewallScope.scrollToRule(f.table, f.chain, f.ruleIdx);
        });
        list.appendChild(row);
      }
      lintContent.appendChild(list);
    }

    function exportLint(kind, report) {
      const fmt = (lastResult && lastResult.format) || 'unknown';
      const generatedAt = new Date().toISOString();
      const today = generatedAt.slice(0, 10);
      if (kind === 'json') {
        const payload = {
          generator: 'FirewallScope',
          generatedAt,
          source: { format: fmt },
          counts: report.counts,
          findings: report.findings
        };
        downloadBlob(new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' }),
                     `firewallscope-lint-${today}.json`);
        return;
      }
      if (kind === 'md') {
        const text = buildLintMarkdown(report, fmt, generatedAt);
        downloadBlob(new Blob([text], { type: 'text/markdown' }),
                     `firewallscope-lint-${today}.md`);
      }
    }

    function buildLintMarkdown(report, format, generatedAt) {
      const lines = ['# FirewallScope lint report', ''];
      lines.push(`- Source format: \`${format}\``);
      lines.push(`- Generated: ${generatedAt}`);
      lines.push('', '## Summary', '');
      const c = report.counts;
      if (c.error)   lines.push(`- ${c.error} error${c.error !== 1 ? 's' : ''}`);
      if (c.warning) lines.push(`- ${c.warning} warning${c.warning !== 1 ? 's' : ''}`);
      if (c.info)    lines.push(`- ${c.info} info`);
      if (c.total === 0) lines.push('- No findings.');
      lines.push('');

      const order = { error: 0, warning: 1, info: 2 };
      const sorted = report.findings.slice().sort((a, b) =>
        order[a.severity] - order[b.severity] ||
        (a.table || '').localeCompare(b.table || '') ||
        (a.chain || '').localeCompare(b.chain || '') ||
        ((a.ruleIdx == null ? -1 : a.ruleIdx) - (b.ruleIdx == null ? -1 : b.ruleIdx))
      );

      let lastSev = null;
      for (const f of sorted) {
        if (f.severity !== lastSev) {
          lastSev = f.severity;
          const label = f.severity.charAt(0).toUpperCase() + f.severity.slice(1);
          lines.push(`## ${label}s`, '');
        }
        const loc = `\`${f.table}\` / \`${f.chain}\``;
        const r = f.ruleIdx == null ? '' : ` rule #${f.ruleIdx + 1}`;
        lines.push(`### ${loc}${r} — \`${f.id}\``, '');
        lines.push(f.title);
        if (f.details) {
          lines.push('', '```', f.details, '```');
        }
        lines.push('');
      }
      return lines.join('\n');
    }

    function formatNatPair(p) {
      if (!p) return '?';
      const ip = p.destination || p.source || 'any';
      const port = p.dport != null ? p.dport : (p.sport != null ? p.sport : null);
      return port != null ? `${ip}:${port}` : ip;
    }

    function downloadBlob(blob, filename) {
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }

    function escapeHtml(s) {
      return String(s).replace(/[&<>"']/g, c => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
      }[c]));
    }

    function countStats(result) {
      let chains = 0, rules = 0;
      for (const t of result.tables) {
        chains += t.chains.length;
        for (const c of t.chains) rules += c.rules.length;
      }
      return { tables: result.tables.length, chains, rules };
    }

    function showError(msg) {
      parseError.textContent = msg;
      parseError.hidden = false;
    }
    function hideError() {
      parseError.hidden = true;
      parseError.textContent = '';
    }
    function showWarnings(list) {
      const ul = document.createElement('ul');
      for (const w of list.slice(0, 50)) {
        const li = document.createElement('li');
        li.textContent = w;
        ul.appendChild(li);
      }
      if (list.length > 50) {
        const li = document.createElement('li');
        li.textContent = `…and ${list.length - 50} more`;
        ul.appendChild(li);
      }
      parseWarn.innerHTML = `<b>${list.length} warning${list.length !== 1 ? 's' : ''}</b>`;
      parseWarn.appendChild(ul);
      parseWarn.hidden = false;
    }
    function hideWarnings() {
      parseWarn.hidden = true;
      parseWarn.innerHTML = '';
    }
    function clearGraph() {
      const cy = window.FirewallScope.cy;
      if (cy) cy.elements().remove();
    }
    function clearTable() {
      document.getElementById('table-content').innerHTML = '';
    }

    // Deep-link support: ?sample=portforward&tab=graph auto-loads a built-in
    // sample and switches to the requested tab. Useful for shareable demo
    // URLs and for capturing screenshots from a headless browser without
    // having to click through the UI.
    const params = new URLSearchParams(window.location.search);
    const sampleKey = params.get('sample');
    const tabKey = params.get('tab');
    if (sampleKey && SAMPLE_URLS[sampleKey]) {
      loadSample(sampleKey).then(() => {
        if (tabKey && ['graph', 'table', 'lint', 'trace'].includes(tabKey)) {
          switchTab(tabKey);
        }
      });
    } else if (tabKey && ['graph', 'table', 'lint', 'trace'].includes(tabKey)) {
      switchTab(tabKey);
    }
  });
})();
