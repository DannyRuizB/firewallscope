(function () {
  'use strict';

  const SAMPLE_URLS = {
    iptables:  'samples/iptables-save.txt',
    ip6tables: 'samples/ip6tables-save.txt',
    nftables:  'samples/nft-ruleset.txt',
    ufw:       'samples/ufw-status.txt'
  };

  const FORMAT_LABELS = {
    iptables:  'iptables-save (IPv4)',
    ip6tables: 'ip6tables-save (IPv6)',
    nftables:  'nft list ruleset',
    ufw:       'ufw status verbose'
  };

  let lastResult = null;

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
    const graphView    = document.getElementById('graph-view');
    const tableView    = document.getElementById('table-view');
    const graphEmpty   = document.getElementById('graph-empty');
    const tableEmpty   = document.getElementById('table-empty');

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

    function switchTab(which) {
      const isGraph = which === 'graph';
      tabGraph.classList.toggle('active', isGraph);
      tabTable.classList.toggle('active', !isGraph);
      graphView.hidden = !isGraph;
      tableView.hidden = isGraph;
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
      hideError();
      hideWarnings();
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
      const result = window.FirewallScope.parse(text, opts);

      if (result.error) {
        showError(result.error);
        formatBadge.hidden = true;
        graphEmpty.hidden = false;
        tableEmpty.hidden = false;
        lastResult = null;
        clearGraph();
        clearTable();
        return;
      }

      const stats = countStats(result);
      formatBadge.innerHTML =
        `<b>${FORMAT_LABELS[result.format] || result.format}</b> · ${stats.tables} table${stats.tables !== 1 ? 's' : ''} · ${stats.chains} chain${stats.chains !== 1 ? 's' : ''} · ${stats.rules} rule${stats.rules !== 1 ? 's' : ''}`;
      formatBadge.hidden = false;

      if (result.warnings && result.warnings.length) {
        showWarnings(result.warnings);
      }

      lastResult = result;
      graphEmpty.hidden = true;
      tableEmpty.hidden = true;
      if (!graphView.hidden) {
        window.FirewallScope.renderGraph(result);
      }
      window.FirewallScope.renderTable(result);
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
