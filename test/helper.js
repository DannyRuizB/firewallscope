'use strict';

// Test harness for the browser modules without a browser or a bundler.
//
// Each file in src/ is an IIFE that hangs its public API off `window`. We load
// the pure-logic modules into a single vm sandbox whose global doubles as
// `window`, then hand back the assembled FirewallScope namespace. The DOM-bound
// modules (app.js, graph.js) are deliberately skipped — they need a real DOM
// and the cytoscape CDN globals, and carry no parsing/linting logic to test.

const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const SRC = path.join(ROOT, 'src');
const SAMPLES = path.join(ROOT, 'samples');

// Dependency order: leaf parsers and helpers before the modules that call them.
const MODULES = [
  'parsers/iptables.js',
  'parsers/ip6tables.js',
  'parsers/nftables.js',
  'parsers/ufw.js',
  'trace.js',
  'diff.js',
  'linter.js',
  'parser.js',
];

function loadFirewallScope() {
  const sandbox = { console };
  sandbox.window = sandbox; // window.X writes land on the sandbox global
  vm.createContext(sandbox);
  for (const rel of MODULES) {
    const code = fs.readFileSync(path.join(SRC, rel), 'utf8');
    vm.runInContext(code, sandbox, { filename: rel });
  }
  return sandbox.FirewallScope;
}

function sample(name) {
  return fs.readFileSync(path.join(SAMPLES, name), 'utf8');
}

module.exports = { loadFirewallScope, sample };
