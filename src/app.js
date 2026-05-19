(function () {
  'use strict';

  const SAMPLE_URLS = {
    iptables:  'samples/iptables-save.txt',
    ip6tables: 'samples/ip6tables-save.txt',
    nftables:  'samples/nft-ruleset.txt',
    ufw:       'samples/ufw-status.txt',
    leaky:     'samples/iptables-leaky.txt',
    shadowed:  'samples/iptables-shadowed.txt'
  };

  const FORMAT_LABELS = {
    iptables:  'iptables-save (IPv4)',
    ip6tables: 'ip6tables-save (IPv6)',
    nftables:  'nft list ruleset',
    ufw:       'ufw status verbose'
  };

  let lastResult = null;
  let lastLintReport = null;

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
    const graphView    = document.getElementById('graph-view');
    const tableView    = document.getElementById('table-view');
    const lintView     = document.getElementById('lint-view');
    const lintContent  = document.getElementById('lint-content');
    const lintEmpty    = document.getElementById('lint-empty');
    const lintClean    = document.getElementById('lint-clean');
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
      tabGraph.classList.toggle('active', isGraph);
      tabTable.classList.toggle('active', isTable);
      tabLint .classList.toggle('active', isLint);
      graphView.hidden = !isGraph;
      tableView.hidden = !isTable;
      lintView .hidden = !isLint;
      exportWrap.hidden = !isGraph;
      if (!isGraph) {
        exportMenu.hidden = true;
        exportToggle.setAttribute('aria-expanded', 'false');
      }
      if (isGraph && lastResult && window.FirewallScope.renderGraph) {
        window.FirewallScope.renderGraph(lastResult);
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

      if (!graphView.hidden) {
        window.FirewallScope.renderGraph(result, lintReport);
      }
      window.FirewallScope.renderTable(result, lintReport);
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
          switchTab('table');
          // The table view is already rendered with pills; scroll to the target rule.
          window.FirewallScope.scrollToRule &&
            window.FirewallScope.scrollToRule(f.table, f.chain, f.ruleIdx);
        });
        list.appendChild(row);
      }
      lintContent.appendChild(list);
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
  });
})();
