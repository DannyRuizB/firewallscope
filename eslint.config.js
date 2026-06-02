const js = require('@eslint/js');
const globals = require('globals');

module.exports = [
  js.configs.recommended,
  {
    files: ['src/**/*.js'],
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'script',
      globals: {
        ...globals.browser,
        // Loaded from CDN <script> tags in index.html, not bundled.
        cytoscape: 'readonly',
        dagre: 'readonly',
        cytoscapeDagre: 'readonly',
        cytoscapeSvg: 'readonly',
        cytoscapeGridGuide: 'readonly',
      },
    },
    rules: {
      // Allow intentional throwaway bindings named _ (e.g. catch (_) {}).
      'no-unused-vars': ['error', {
        argsIgnorePattern: '^_',
        varsIgnorePattern: '^_',
        caughtErrors: 'all',
        caughtErrorsIgnorePattern: '^_',
      }],
    },
  },
];
