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
      addedRules: 0, removedRules: 0, sameRules: 0
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
          const setA = new Set(cA.rules.map(r => normalizeRaw(r.raw)));
          const setB = new Set(cB.rules.map(r => normalizeRaw(r.raw)));

          const mergedRules = [];
          for (const r of cB.rules) {
            const n = normalizeRaw(r.raw);
            if (setA.has(n)) {
              mergedRules.push({ ...r, diffState: 'same' });
              stats.sameRules++;
            } else {
              mergedRules.push({ ...r, diffState: 'added' });
              stats.addedRules++;
            }
          }
          for (const r of cA.rules) {
            const n = normalizeRaw(r.raw);
            if (!setB.has(n)) {
              mergedRules.push({ ...r, diffState: 'removed' });
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

  window.FirewallScope = window.FirewallScope || {};
  window.FirewallScope.mergeForDiff = mergeForDiff;
})();
