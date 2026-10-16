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

// The release line at the top of the README names every smell and counts
// them. It drifted twice (67 listed while the linter had 69): now the list
// and the number are checked against the ids the linter actually emits.
test('the README lists and counts exactly the smells the linter has', () => {
  const linter = fs.readFileSync(path.join(root, 'src', 'linter.js'), 'utf8');
  const readme = fs.readFileSync(path.join(root, 'README.md'), 'utf8');
  const ids = new Set([...linter.matchAll(/\bid: '([a-z0-9-]+)'/g)].map((m) => m[1]));
  const m = readme.match(/\*\*Linter\*\* with (\d+) smells \(([^)]*)\)/);
  assert.ok(m, 'the README release line no longer says "**Linter** with N smells (…)"');
  const listed = m[2].split(',').map((x) => x.trim());
  assert.equal(new Set(listed).size, listed.length, 'a smell is listed twice');
  assert.deepEqual([...ids].filter((id) => !listed.includes(id)), [], 'smells missing from the README list');
  assert.deepEqual(listed.filter((id) => !ids.has(id)), [], 'README lists smells the linter does not have');
  assert.equal(Number(m[1]), ids.size, 'the README count');
});
