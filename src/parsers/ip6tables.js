(function () {
  'use strict';

  function parseIp6tablesSave(text) {
    if (typeof window.parseIptablesSave !== 'function') {
      throw new Error('parseIptablesSave must be loaded before parseIp6tablesSave');
    }
    return window.parseIptablesSave(text, 'ip6tables');
  }

  window.parseIp6tablesSave = parseIp6tablesSave;
})();
