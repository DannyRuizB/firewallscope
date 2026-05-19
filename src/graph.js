(function () {
  'use strict';

  let cyInstance = null;

  function renderGraph(result) {
    const container = document.getElementById('graph');
    if (!container) return;

    if (cyInstance) {
      cyInstance.destroy();
      cyInstance = null;
    }

    const elements = buildElements(result);
    if (!elements.length) return;

    cyInstance = cytoscape({
      container,
      elements,
      style: graphStyle(),
      layout: { name: 'dagre', rankDir: 'LR', nodeSep: 30, rankSep: 70, padding: 20 },
      wheelSensitivity: 0.2,
      minZoom: 0.2,
      maxZoom: 3
    });

    cyInstance.fit(undefined, 30);
    cyInstance.center();

    cyInstance.on('tap', 'node[type = "chain"]', (e) => {
      const data = e.target.data();
      switchToTableAndScrollTo(data.tableName, data.chainName);
    });

    cyInstance.on('mouseover', 'node[type = "chain"]', (e) => {
      showTooltip(e.target);
    });
    cyInstance.on('mouseout', 'node[type = "chain"]', () => {
      hideTooltip();
    });
    cyInstance.on('pan zoom', () => {
      hideTooltip();
    });

    window.FirewallScope.cy = cyInstance;
  }

  function showTooltip(node) {
    const tt = document.getElementById('chain-tooltip');
    if (!tt) return;
    const d = node.data();

    let html = `<div class="tt-title">${escapeHtml(d.chainName)}</div>`;
    const metaBits = [];
    if (d.tableName) metaBits.push(`table ${escapeHtml(d.tableName)}${d.tableFamily ? ` [${escapeHtml(d.tableFamily)}]` : ''}`);
    if (d.policy) metaBits.push(`policy ${escapeHtml(d.policy)}`);
    else if (!d.builtIn) metaBits.push('user-defined');
    if (d.hook) metaBits.push(`hook ${escapeHtml(d.hook)}`);
    if (d.priority) metaBits.push(`priority ${escapeHtml(d.priority)}`);
    if (metaBits.length) html += `<div class="tt-meta">${metaBits.join(' · ')}</div>`;

    const stats = [];
    if (d.accept) stats.push(`<span class="tt-stat tt-stat-accept">${d.accept} ACCEPT</span>`);
    if (d.drop)   stats.push(`<span class="tt-stat tt-stat-drop">${d.drop} DROP</span>`);
    if (d.reject) stats.push(`<span class="tt-stat tt-stat-reject">${d.reject} REJECT</span>`);
    if (d.jump)   stats.push(`<span class="tt-stat tt-stat-jump">${d.jump} jump</span>`);
    if (d.other)  stats.push(`<span class="tt-stat tt-stat-other">${d.other} other</span>`);
    if (stats.length) html += `<div class="tt-stats">${stats.join('')}</div>`;
    else html += `<div class="tt-meta">(no rules)</div>`;

    const comments = d.comments || [];
    if (comments.length) {
      html += `<div class="tt-comments-title">Comments</div>`;
      for (const c of comments.slice(0, 5)) {
        html += `<div class="tt-comment">${escapeHtml(c)}</div>`;
      }
      if (comments.length > 5) {
        html += `<div class="tt-more">…and ${comments.length - 5} more</div>`;
      }
    }

    tt.innerHTML = html;

    const bb = node.renderedBoundingBox();
    const view = document.getElementById('graph-view');
    const viewW = view.clientWidth;
    const viewH = view.clientHeight;
    tt.hidden = false;
    const tw = tt.offsetWidth;
    const th = tt.offsetHeight;

    let left = bb.x2 + 12;
    let top  = bb.y1;
    if (left + tw > viewW - 10) left = Math.max(10, bb.x1 - tw - 12);
    if (top + th > viewH - 10)  top  = Math.max(10, viewH - th - 10);
    tt.style.left = `${left}px`;
    tt.style.top  = `${top}px`;
  }

  function hideTooltip() {
    const tt = document.getElementById('chain-tooltip');
    if (tt) tt.hidden = true;
  }

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function buildElements(result) {
    const elements = [];
    const chainIdSet = new Set();

    for (const table of result.tables) {
      const tableId = `t:${table.name}${table.family ? '@' + table.family : ''}`;
      const familyLabel = table.family ? ` [${table.family}]` : '';
      elements.push({
        data: {
          id: tableId,
          label: table.name + familyLabel,
          type: 'table'
        }
      });

      for (const chain of table.chains) {
        const chainId = `${tableId}::${chain.name}`;
        chainIdSet.add(chainId);
        const stats = countRuleActions(chain.rules);
        const policyText = chain.policy ? ` · policy ${chain.policy}` : (chain.builtIn ? '' : ' · user');
        const ruleSummary = `${chain.rules.length} rule${chain.rules.length !== 1 ? 's' : ''}`;
        const label = `${chain.name}\n${ruleSummary}${policyText}`;
        const comments = chain.rules.map(r => r.comment).filter(Boolean);

        let chainDiff = chain.diffState || null;
        let hasInnerDiff = false;
        if (chainDiff === 'same' && Array.isArray(chain.rules)) {
          for (const r of chain.rules) {
            if (r.diffState === 'added' || r.diffState === 'removed') { hasInnerDiff = true; break; }
          }
        }
        const diffState = chainDiff === 'same' && hasInnerDiff ? 'changed' : chainDiff;

        elements.push({
          data: {
            id: chainId,
            parent: tableId,
            label,
            type: 'chain',
            chainName: chain.name,
            tableName: table.name,
            tableFamily: table.family || null,
            policy: chain.policy,
            builtIn: chain.builtIn,
            hook: chain.hook || null,
            priority: chain.priority || null,
            accept: stats.accept,
            drop: stats.drop,
            reject: stats.reject,
            jump: stats.jump,
            other: stats.other,
            comments,
            diffState
          }
        });
      }
    }

    for (const table of result.tables) {
      const tableId = `t:${table.name}${table.family ? '@' + table.family : ''}`;
      for (const chain of table.chains) {
        const srcId = `${tableId}::${chain.name}`;
        const jumpCount = {};
        for (const rule of chain.rules) {
          if (rule.isJumpToChain && rule.action) {
            jumpCount[rule.action] = (jumpCount[rule.action] || 0) + 1;
          }
        }
        for (const [target, count] of Object.entries(jumpCount)) {
          const targetId = `${tableId}::${target}`;
          if (!chainIdSet.has(targetId)) continue;
          elements.push({
            data: {
              id: `e:${srcId}->${targetId}`,
              source: srcId,
              target: targetId,
              label: count > 1 ? `${count}×` : '',
              type: 'jump'
            }
          });
        }
      }
    }

    return elements;
  }

  function countRuleActions(rules) {
    const out = { accept: 0, drop: 0, reject: 0, jump: 0, other: 0 };
    for (const r of rules) {
      if (r.isJumpToChain)          out.jump++;
      else if (r.action === 'ACCEPT') out.accept++;
      else if (r.action === 'DROP')   out.drop++;
      else if (r.action === 'REJECT') out.reject++;
      else                            out.other++;
    }
    return out;
  }

  function graphStyle() {
    return [
      {
        selector: 'node[type = "table"]',
        style: {
          'background-color': 'rgba(51,65,85,0.25)',
          'border-color': '#475569',
          'border-width': 1,
          'border-style': 'dashed',
          'shape': 'round-rectangle',
          'label': 'data(label)',
          'color': '#94a3b8',
          'font-family': 'JetBrains Mono, Courier New, monospace',
          'font-size': 11,
          'font-weight': 600,
          'text-valign': 'top',
          'text-halign': 'center',
          'text-margin-y': -6,
          'padding': 14,
          'text-transform': 'uppercase'
        }
      },
      {
        selector: 'node[type = "chain"]',
        style: {
          'background-color': '#1e293b',
          'border-width': 1.5,
          'border-color': '#475569',
          'shape': 'round-rectangle',
          'width': 130,
          'height': 50,
          'label': 'data(label)',
          'color': '#e2e8f0',
          'font-family': 'JetBrains Mono, Courier New, monospace',
          'font-size': 11,
          'text-valign': 'center',
          'text-halign': 'center',
          'text-wrap': 'wrap',
          'text-max-width': 120,
          'line-height': 1.3
        }
      },
      {
        selector: 'node[type = "chain"][policy = "ACCEPT"]',
        style: {
          'border-color': '#16a34a',
          'background-color': '#14532d'
        }
      },
      {
        selector: 'node[type = "chain"][policy = "DROP"]',
        style: {
          'border-color': '#dc2626',
          'background-color': '#7f1d1d',
          'color': '#fff'
        }
      },
      {
        selector: 'node[type = "chain"][policy = "REJECT"]',
        style: {
          'border-color': '#f97316',
          'background-color': '#7c2d12'
        }
      },
      {
        selector: 'node[type = "chain"][!builtIn]',
        style: {
          'border-style': 'dashed',
          'border-color': '#dc2626',
          'background-color': '#1e293b'
        }
      },
      {
        selector: 'edge[type = "jump"]',
        style: {
          'curve-style': 'bezier',
          'width': 1.5,
          'line-color': '#94a3b8',
          'target-arrow-color': '#94a3b8',
          'target-arrow-shape': 'triangle',
          'label': 'data(label)',
          'font-size': 10,
          'color': '#94a3b8',
          'font-family': 'JetBrains Mono, monospace',
          'text-background-color': '#0f172a',
          'text-background-opacity': 1,
          'text-background-padding': 2
        }
      },
      {
        selector: 'node[type = "chain"][diffState = "added"]',
        style: {
          'border-color': '#22c55e',
          'border-style': 'solid',
          'border-width': 3,
          'background-color': '#14532d',
          'color': '#86efac'
        }
      },
      {
        selector: 'node[type = "chain"][diffState = "removed"]',
        style: {
          'border-color': '#dc2626',
          'border-style': 'dashed',
          'border-width': 3,
          'background-color': '#1f0f10',
          'color': '#fca5a5',
          'opacity': 0.6
        }
      },
      {
        selector: 'node[type = "chain"][diffState = "changed"]',
        style: {
          'border-color': '#f59e0b',
          'border-style': 'solid',
          'border-width': 3
        }
      },
      {
        selector: 'node:selected',
        style: {
          'border-color': '#dc2626',
          'border-width': 3
        }
      }
    ];
  }

  /* ─── table view ────────────────────────────── */

  function renderTable(result) {
    const root = document.getElementById('table-content');
    if (!root) return;
    root.innerHTML = '';

    for (const table of result.tables) {
      const section = document.createElement('div');
      section.className = 'tbl-table';
      section.dataset.tableName = table.name;
      const h3 = document.createElement('h3');
      h3.textContent = `*${table.name}`;
      if (table.family) {
        const span = document.createElement('span');
        span.className = 'family';
        span.textContent = `family: ${table.family}`;
        h3.appendChild(span);
      }
      section.appendChild(h3);

      for (const chain of table.chains) {
        section.appendChild(renderChain(chain));
      }

      root.appendChild(section);
    }
  }

  function renderChain(chain) {
    const wrap = document.createElement('div');
    wrap.className = 'tbl-chain';
    wrap.dataset.chainName = chain.name;
    if (chain.diffState === 'added')   wrap.classList.add('diff-added');
    if (chain.diffState === 'removed') wrap.classList.add('diff-removed');

    const header = document.createElement('div');
    header.className = 'tbl-chain-header';

    const nameSpan = document.createElement('span');
    nameSpan.className = 'tbl-chain-name';
    nameSpan.textContent = chain.name;
    if (chain.policyChanged) {
      const pill = document.createElement('span');
      pill.className = 'policy-pill policy-none';
      pill.textContent = `policy ${chain.policyA || '—'} → ${chain.policyB || '—'}`;
      nameSpan.appendChild(pill);
    } else if (chain.policy) {
      const pill = document.createElement('span');
      pill.className = 'policy-pill ' + policyClass(chain.policy);
      pill.textContent = `policy ${chain.policy}`;
      nameSpan.appendChild(pill);
    } else if (!chain.builtIn) {
      const pill = document.createElement('span');
      pill.className = 'policy-pill policy-none';
      pill.textContent = 'user';
      nameSpan.appendChild(pill);
    }
    if (chain.diffState === 'added' || chain.diffState === 'removed') {
      const stateBadge = document.createElement('span');
      stateBadge.className = 'tbl-chain-state ' + chain.diffState;
      stateBadge.textContent = chain.diffState === 'added' ? '+ added' : '− removed';
      nameSpan.appendChild(stateBadge);
    }
    header.appendChild(nameSpan);

    const meta = document.createElement('span');
    meta.className = 'tbl-chain-meta';
    let metaText = `${chain.rules.length} rule${chain.rules.length !== 1 ? 's' : ''}`;
    if (chain.hook) metaText += ` · hook ${chain.hook}`;
    if (chain.priority) metaText += ` · priority ${chain.priority}`;
    meta.textContent = metaText;
    header.appendChild(meta);

    wrap.appendChild(header);

    if (!chain.rules.length) {
      const empty = document.createElement('div');
      empty.className = 'empty-rules';
      empty.textContent = '(no rules)';
      wrap.appendChild(empty);
      return wrap;
    }

    const tbl = document.createElement('table');
    tbl.className = 'tbl-rules';
    chain.rules.forEach((rule, i) => {
      const tr = document.createElement('tr');
      if (rule.diffState === 'added')   tr.classList.add('diff-added');
      if (rule.diffState === 'removed') tr.classList.add('diff-removed');

      const tdNum = document.createElement('td');
      tdNum.className = 'col-num';
      tdNum.textContent = i + 1;
      tr.appendChild(tdNum);

      const tdMatch = document.createElement('td');
      tdMatch.className = 'col-match';
      tdMatch.textContent = rule.match || '(any)';
      tr.appendChild(tdMatch);

      const tdAction = document.createElement('td');
      tdAction.className = 'col-action';
      const pill = document.createElement('span');
      pill.className = 'action-pill ' + actionClass(rule);
      pill.textContent = formatActionLabel(rule);
      tdAction.appendChild(pill);
      tr.appendChild(tdAction);

      const tdComment = document.createElement('td');
      tdComment.className = 'col-comment';
      tdComment.textContent = rule.comment ? `# ${rule.comment}` : '';
      tr.appendChild(tdComment);

      tbl.appendChild(tr);
    });
    wrap.appendChild(tbl);

    return wrap;
  }

  function policyClass(policy) {
    if (policy === 'ACCEPT') return 'policy-accept';
    if (policy === 'DROP') return 'policy-drop';
    if (policy === 'REJECT') return 'policy-reject';
    return 'policy-none';
  }

  function actionClass(rule) {
    if (rule.isJumpToChain) return 'action-jump';
    if (rule.action === 'ACCEPT') return 'action-accept';
    if (rule.action === 'DROP')   return 'action-drop';
    if (rule.action === 'REJECT') return 'action-reject';
    return 'action-other';
  }

  function formatActionLabel(rule) {
    if (rule.isJumpToChain) return (rule.isGoto ? 'goto ' : 'jump ') + rule.action;
    if (!rule.action) return '?';
    const detail = rule.actionDetail ? ` ${rule.actionDetail}` : '';
    return rule.action + detail;
  }

  function switchToTableAndScrollTo(tableName, chainName) {
    const tabTable = document.getElementById('tab-table');
    if (tabTable) tabTable.click();
    requestAnimationFrame(() => {
      const sel = `.tbl-table[data-table-name="${cssEscape(tableName)}"] .tbl-chain[data-chain-name="${cssEscape(chainName)}"]`;
      const el = document.querySelector(sel);
      if (el) {
        el.scrollIntoView({ behavior: 'smooth', block: 'start' });
        el.style.outline = '2px solid var(--accent)';
        setTimeout(() => { el.style.outline = ''; }, 1500);
      }
    });
  }

  function cssEscape(s) {
    return String(s).replace(/(["\\])/g, '\\$1');
  }

  function exportGraph(format) {
    if (!cyInstance) return;
    if (format === 'png') {
      const blob = cyInstance.png({ bg: '#0f172a', full: true, scale: 2, output: 'blob' });
      downloadBlob(blob, 'firewallscope.png');
      return;
    }
    if (format === 'svg') {
      if (typeof cyInstance.svg !== 'function') {
        console.error('SVG export plugin not loaded (cytoscape-svg).');
        return;
      }
      const svgText = cyInstance.svg({ scale: 1, full: true, bg: '#0f172a' });
      downloadBlob(new Blob([svgText], { type: 'image/svg+xml' }), 'firewallscope.svg');
    }
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

  window.FirewallScope = window.FirewallScope || {};
  window.FirewallScope.renderGraph = renderGraph;
  window.FirewallScope.renderTable = renderTable;
  window.FirewallScope.exportGraph = exportGraph;
})();
