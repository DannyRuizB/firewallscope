'use strict';

// Every sample a release ships has to be reachable from the UI's "Load sample"
// dropdown: an entry in the SAMPLES map of src/app.js and a button in
// index.html. The `*-after.txt` files are the diff companions (see the README)
// and are loaded through the compare view, not the dropdown.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const app = fs.readFileSync(path.join(root, 'src', 'app.js'), 'utf8');
const html = fs.readFileSync(path.join(root, 'index.html'), 'utf8');

test('every sample is wired into the Load sample dropdown', () => {
  const files = fs.readdirSync(path.join(root, 'samples')).filter((n) => !n.endsWith('-after.txt'));
  assert.ok(files.length > 0);
  for (const name of files) {
    const m = app.match(new RegExp(`^\\s*(\\w+):\\s*'samples/${name.replace(/\./g, '\\.')}'`, 'm'));
    assert.ok(m, `${name} has no entry in the SAMPLES map of src/app.js`);
    assert.ok(html.includes(`data-sample="${m[1]}"`), `${name} (key ${m[1]}) has no button in index.html`);
  }
});
