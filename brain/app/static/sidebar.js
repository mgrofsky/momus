/* Keep the desktop navigation preference across full-page routes. */
(() => {
  'use strict';

  const key = 'momus-sidebar-collapsed';
  const root = document.documentElement;

  try {
    if (localStorage.getItem(key) === '1') root.classList.add('sidebar-collapsed');
  } catch (_) {
    // The menu still works for this page if storage is unavailable.
  }

  const bindToggle = () => {
    const toggle = document.querySelector('.sidebar-toggle');
    if (!toggle) return;

    const sync = () => {
      const collapsed = root.classList.contains('sidebar-collapsed');
      const label = collapsed ? 'Expand menu' : 'Collapse menu';
      toggle.setAttribute('aria-expanded', String(!collapsed));
      toggle.setAttribute('aria-label', label);
      toggle.title = label;
    };

    sync();
    toggle.addEventListener('click', () => {
      const collapsed = root.classList.toggle('sidebar-collapsed');
      try {
        localStorage.setItem(key, collapsed ? '1' : '0');
      } catch (_) {
        // Keep the current page interactive without persistent storage.
      }
      sync();
    });
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', bindToggle, { once: true });
  } else {
    bindToggle();
  }
})();
