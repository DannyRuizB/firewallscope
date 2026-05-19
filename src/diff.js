(function () {
  'use strict';

  function mergeForDiff(resultA, resultB) {
    if (resultA.format !== resultB.format) {
      return {
        error: `Cross-format diff not supported (left is ${resultA.format}, right is ${resultB.format}). Both rulesets must be the same format.`,
        isDiff: true,
        format: null,
        tables: [],
        diff: null,
        warnings: []
      };
    }

    const tableKeys = new Set();
    const indexA = {}, indexB = {};
    for (const t of resultA.tables) {
      const key = `${t.family || ''}::${t.name}`;
      indexA[key] = t;
      tableKeys.add(key);
    }
    for (const t of resultB.tables) {
      const key = `${t.family || ''}::${t.name}`;
      indexB[key] = t;
      tableKeys.add(key);
    }

    const stats = {
      addedTables: 0, removedTables: 0,
      addedChains: 0, removedChains: 0, commonChains: 0,
      addedRules: 0, removedRules: 0, sameRules: 0, movedRules: 0
    };

    const mergedTables = [];

    for (const tKey of tableKeys) {
      const tA = indexA[tKey];
      const tB = indexB[tKey];

      let diffState, baseTable;
      if (!tA && tB)      { diffState = 'added';   baseTable = tB; stats.addedTables++; }
      else if (tA && !tB) { diffState = 'removed'; baseTable = tA; stats.removedTables++; }
      else                { diffState = 'same';    baseTable = tB; }

      const chainNames = new Set();
      if (tA) for (const c of tA.chains) chainNames.add(c.name);
      if (tB) for (const c of tB.chains) chainNames.add(c.name);

      const mergedChains = [];
      for (const cName of chainNames) {
        const cA = tA ? tA.chains.find(c => c.name === cName) : null;
        const cB = tB ? tB.chains.find(c => c.name === cName) : null;

        if (!cA && cB) {
          stats.addedChains++;
          stats.addedRules += cB.rules.length;
          mergedChains.push({
            ...cB,
            diffState: 'added',
            rules: cB.rules.map(r => ({ ...r, diffState: 'added' }))
          });
        } else if (cA && !cB) {
          stats.removedChains++;
          stats.removedRules += cA.rules.length;
          mergedChains.push({
            ...cA,
            diffState: 'removed',
            rules: cA.rules.map(r => ({ ...r, diffState: 'removed' }))
          });
        } else {
          stats.commonChains++;
          const arrA = cA.rules.map(r => normalizeRaw(r.raw));
          const arrB = cB.rules.map(r => normalizeRaw(r.raw));
          const lcsRes = lcs(arrA, arrB);
          const lcsA = new Set(lcsRes.idxA);
          const lcsB = new Set(lcsRes.idxB);

          // Indices in A available to claim as the "source" of a moved rule
          // (i.e. in A, same raw, not part of LCS). Multiset-safe: pop the
          // first available match each time a B-side moved rule consumes one.
          const availableInA = new Map();
          for (let j = 0; j < arrA.length; j++) {
            if (lcsA.has(j)) continue;
            const k = arrA[j];
            if (!availableInA.has(k)) availableInA.set(k, []);
            availableInA.get(k).push(j);
          }

          const mergedRules = [];
          for (let i = 0; i < cB.rules.length; i++) {
            const r = cB.rules[i];
            const n = arrB[i];
            if (lcsB.has(i)) {
              mergedRules.push({ ...r, diffState: 'same' });
              stats.sameRules++;
            } else if (availableInA.has(n) && availableInA.get(n).length > 0) {
              const fromIdx = availableInA.get(n).shift();
              mergedRules.push({
                ...r,
                diffState: 'moved',
                movedFrom: fromIdx,
                movedTo: i,
                movedDelta: i - fromIdx
              });
              stats.movedRules++;
            } else {
              mergedRules.push({ ...r, diffState: 'added' });
              stats.addedRules++;
            }
          }

          // Whatever instances are still in availableInA after the B pass were
          // not claimed as moved sources → they are genuinely removed.
          for (const [, list] of availableInA) {
            for (const j of list) {
              mergedRules.push({ ...cA.rules[j], diffState: 'removed' });
              stats.removedRules++;
            }
          }

          const policyChanged = cA.policy !== cB.policy;
          mergedChains.push({
            ...cB,
            diffState: 'same',
            policyA: policyChanged ? cA.policy : null,
            policyB: policyChanged ? cB.policy : null,
            policyChanged,
            rules: mergedRules
          });
        }
      }

      mergedTables.push({
        ...baseTable,
        diffState,
        chains: mergedChains
      });
    }

    return {
      format: resultA.format,
      isDiff: true,
      tables: mergedTables,
      diff: stats,
      error: null,
      warnings: [...(resultA.warnings || []), ...(resultB.warnings || [])]
    };
  }

  function normalizeRaw(raw) {
    return String(raw).trim().replace(/\s+/g, ' ');
  }

  // Standard O(n·m) LCS — returns the indices of the common subsequence in
  // each input. Chains have at most a few dozen rules so a Uint16Array DP
  // table is fine.
  function lcs(a, b) {
    const n = a.length, m = b.length;
    if (n === 0 || m === 0) return { idxA: [], idxB: [] };
    const dp = new Uint16Array((n + 1) * (m + 1));
    const stride = m + 1;
    for (let i = 1; i <= n; i++) {
      for (let j = 1; j <= m; j++) {
        dp[i * stride + j] = (a[i - 1] === b[j - 1])
          ? dp[(i - 1) * stride + (j - 1)] + 1
          : Math.max(dp[(i - 1) * stride + j], dp[i * stride + (j - 1)]);
      }
    }
    const idxA = [], idxB = [];
    let i = n, j = m;
    while (i > 0 && j > 0) {
      if (a[i - 1] === b[j - 1]) {
        idxA.push(i - 1);
        idxB.push(j - 1);
        i--; j--;
      } else if (dp[(i - 1) * stride + j] >= dp[i * stride + (j - 1)]) {
        i--;
      } else {
        j--;
      }
    }
    idxA.reverse();
    idxB.reverse();
    return { idxA, idxB };
  }

  window.FirewallScope = window.FirewallScope || {};
  window.FirewallScope.mergeForDiff = mergeForDiff;
})();
