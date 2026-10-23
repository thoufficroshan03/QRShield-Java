/* ==========================================================
   QRShield – main.js  v2
   Splash screen · Page transitions · Dropdown colours · Charts
   ========================================================== */

'use strict';

/* ── 0. Splash Screen Controller ───────────────────────────
   Shows a full-screen branded intro on the very first visit.
   Uses sessionStorage so it only fires once per browser tab.
   ─────────────────────────────────────────────────────────── */
(function () {
  var splash = document.getElementById('qs-splash');
  if (!splash) return;

  // Already seen this session → remove immediately without any flash
  if (sessionStorage.getItem('qs_splash_seen')) {
    splash.classList.add('splash-hidden');
    return;
  }

  // Inject the SVG linear gradient used by the ring stroke
  var svgNS = 'http://www.w3.org/2000/svg';
  var defs  = document.createElementNS(svgNS, 'defs');
  var grad  = document.createElementNS(svgNS, 'linearGradient');
  grad.setAttribute('id', 'splashGrad');
  grad.setAttribute('x1', '0%'); grad.setAttribute('y1', '0%');
  grad.setAttribute('x2', '100%'); grad.setAttribute('y2', '100%');
  var s1 = document.createElementNS(svgNS, 'stop');
  s1.setAttribute('offset', '0%');   s1.setAttribute('stop-color', '#7c3aed');
  var s2 = document.createElementNS(svgNS, 'stop');
  s2.setAttribute('offset', '100%'); s2.setAttribute('stop-color', '#c084fc');
  grad.appendChild(s1); grad.appendChild(s2); defs.appendChild(grad);
  var svg = splash.querySelector('.splash-ring-svg');
  if (svg) svg.prepend(defs);

  // Total display time:
  //   ~1.17s last letter + 0.4s letter duration + 0.9s reading time = ~2.5s
  var HOLD_MS = 2600;

  setTimeout(function () {
    // Step 1: slide up + fade out
    splash.classList.add('splash-exit');

    // Step 2: hide completely after transition ends
    splash.addEventListener('transitionend', function () {
      splash.classList.add('splash-hidden');
    }, { once: true });

    // Mark as seen
    try { sessionStorage.setItem('qs_splash_seen', '1'); } catch (e) {}
  }, HOLD_MS);
})();


/* ── 1. Page Transition Engine ─────────────────────────────
   Uses the View Transition API when available (Chrome 111+),
   falls back to a CSS class + timeout approach.
   ─────────────────────────────────────────────────────────── */
(function () {
  var LEAVE_MS = 150; // matches --dur-normal in CSS pageOut animation

  function navigate(url) {
    if ('startViewTransition' in document) {
      // Native smooth cross-page transition
      document.startViewTransition(function () {
        window.location.href = url;
      });
    } else {
      // Fallback: add leaving class, then navigate after animation
      document.body.classList.add('page-leaving');
      setTimeout(function () {
        window.location.href = url;
      }, LEAVE_MS);
    }
  }

  document.addEventListener('click', function (e) {
    var link = e.target.closest('a[href]');
    if (!link) return;
    var href = link.getAttribute('href');

    // Skip: external, hash-only, download, target, already active
    if (!href ||
        href.startsWith('http') ||
        href.startsWith('//') ||
        href.startsWith('#') ||
        href === '' ||
        link.hasAttribute('download') ||
        link.getAttribute('target') === '_blank' ||
        link.getAttribute('target') === '_self') return;

    e.preventDefault();
    navigate(href);
  });

  // Re-enable buttons when the user navigates back (bfcache)
  window.addEventListener('pageshow', function (e) {
    if (e.persisted) {
      document.body.classList.remove('page-leaving');
      document.querySelectorAll('.js-busy-form button[type="submit"]')
        .forEach(function (b) { b.disabled = false; });
    }
  });
})();

/* ── 2. Busy-form: spinner + disable on submit ─────────────── */
document.querySelectorAll('.js-busy-form').forEach(function (form) {
  form.addEventListener('submit', function () {
    var btn     = form.querySelector('button[type="submit"]');
    if (!btn) return;
    btn.disabled = true;
    var spinner = btn.querySelector('.spinner-border');
    var label   = btn.querySelector('.btn-label');
    if (spinner) spinner.classList.remove('d-none');
    if (label)   label.textContent = 'Analyzing…';
  });
});

/* ── 3. Confirm-before-submit ──────────────────────────────── */
document.querySelectorAll('.js-confirm-form').forEach(function (form) {
  form.addEventListener('submit', function (e) {
    if (!window.confirm(form.dataset.confirm || 'Are you sure?')) e.preventDefault();
  });
});

/* ── 4. Risk-level select colour update ────────────────────────
   Reads the current selected option value and applies a data
   attribute so CSS can colour the select element.
   ─────────────────────────────────────────────────────────── */
function updateLevelSelect(sel) {
  if (!sel) return;
  var val = sel.value;
  sel.setAttribute('data-selected', val);
  // Also colour the selected option itself (works in Firefox/Edge)
  Array.from(sel.options).forEach(function (opt) {
    opt.className = '';
    if (opt.value === 'Low Risk')    opt.className = 'opt-low';
    if (opt.value === 'Medium Risk') opt.className = 'opt-medium';
    if (opt.value === 'High Risk')   opt.className = 'opt-high';
  });
}

document.querySelectorAll('.qs-level-select').forEach(function (sel) {
  updateLevelSelect(sel);
  sel.addEventListener('change', function () { updateLevelSelect(sel); });
});

/* ── 5. Scroll-reveal (Intersection Observer) ─────────────────
   Adds .qs-visible to elements with data-reveal as they enter
   the viewport. CSS handles the actual animation.
   ─────────────────────────────────────────────────────────── */
if ('IntersectionObserver' in window) {
  var revealObs = new IntersectionObserver(function (entries) {
    entries.forEach(function (entry) {
      if (entry.isIntersecting) {
        entry.target.classList.add('qs-visible');
        revealObs.unobserve(entry.target);
      }
    });
  }, { threshold: 0.12 });

  document.querySelectorAll('[data-reveal]').forEach(function (el) {
    revealObs.observe(el);
  });
}

/* ── 6. Dashboard Charts (Chart.js) ────────────────────────── */
var dataEl = document.getElementById('chart-data');
if (dataEl && window.Chart) {
  var data = {
    levels: JSON.parse(dataEl.dataset.levels),
    trend:  JSON.parse(dataEl.dataset.trend)
  };

  // Colour tokens matching the CSS theme
  var textColor  = '#c4aee8';   // --text-muted brightened
  var gridColor  = 'rgba(160,100,255,0.10)';
  var accentLine = '#a855f7';   // --purple-2
  var accentFill = 'rgba(124,58,237,0.18)';

  Chart.defaults.font.family = "'Inter', system-ui, sans-serif";
  Chart.defaults.color       = textColor;

  // Doughnut – Risk distribution
  new Chart(document.getElementById('levelChart'), {
    type: 'doughnut',
    data: {
      labels: Object.keys(data.levels),
      datasets: [{
        data: Object.values(data.levels),
        backgroundColor: [
          'rgba(74,222,128,0.70)',
          'rgba(252,211,77,0.70)',
          'rgba(251,113,133,0.70)'
        ],
        borderColor:  ['#4ade80', '#fcd34d', '#fb7185'],
        borderWidth: 2,
        hoverOffset: 10
      }]
    },
    options: {
      maintainAspectRatio: false,
      cutout: '68%',
      animation: { duration: 900, easing: 'easeOutQuart' },
      plugins: {
        legend: {
          labels: {
            color: textColor,
            padding: 18,
            font: { size: 12, weight: '600' }
          }
        }
      }
    }
  });

  // Line – Scans per day
  new Chart(document.getElementById('trendChart'), {
    type: 'line',
    data: {
      labels: data.trend.labels,
      datasets: [{
        label: 'Scans',
        data:  data.trend.values,
        borderColor:     accentLine,
        backgroundColor: accentFill,
        fill: true,
        tension: 0.38,
        pointBackgroundColor: accentLine,
        pointBorderColor:     '#0d0618',
        pointBorderWidth: 2,
        pointRadius: 4,
        pointHoverRadius: 7,
        pointHoverBackgroundColor: '#e9d5ff'
      }]
    },
    options: {
      maintainAspectRatio: false,
      animation: { duration: 900, easing: 'easeOutQuart' },
      scales: {
        x: {
          ticks: { color: textColor, maxRotation: 45, font: { size: 11 } },
          grid:  { color: gridColor }
        },
        y: {
          beginAtZero: true,
          ticks: { color: textColor, precision: 0, font: { size: 11 } },
          grid:  { color: gridColor }
        }
      },
      plugins: {
        legend: { labels: { color: textColor, font: { size: 12, weight: '600' } } },
        tooltip: {
          backgroundColor: 'rgba(20,6,40,0.92)',
          borderColor:  'rgba(168,85,247,0.4)',
          borderWidth: 1,
          titleColor: '#e9d5ff',
          bodyColor:  '#c4aee8',
          padding: 10,
          cornerRadius: 10
        }
      }
    }
  });
}
