/* ================================================================
   M3 Royal Wealth — Calculator Core (shared math + formatters)
   Attached to window.M3 so every calculator template can use it
   without module loading. All functions use end-of-month convention
   and return numbers rounded only at display time (never in math).
   ================================================================ */
(function (global) {
  'use strict';

  // ---------- CURRENCY (locale-aware) ----------
  // Single source of truth: localStorage['m3-currency'] ∈ {'indian','western'}.
  // 'indian'  → ₹ with en-IN grouping (1,00,000) + Cr/L/K short form
  // 'western' → $ with en-US grouping (1,000,000) + B/M/K short form
  function getCurrency() {
    try {
      var v = localStorage.getItem('m3-currency');
      if (v === 'indian' || v === 'western') return v;
    } catch (e) {}
    return 'indian';
  }
  function setCurrency(mode) {
    if (mode !== 'indian' && mode !== 'western') return;
    try { localStorage.setItem('m3-currency', mode); } catch (e) {}
    try { window.dispatchEvent(new CustomEvent('m3-currency-change', { detail: mode })); } catch (e) {}
  }
  function currencySymbol() { return getCurrency() === 'western' ? '$' : '₹'; }
  function currencyLocale() { return getCurrency() === 'western' ? 'en-US' : 'en-IN'; }

  // ---------- FORMATTERS (currency-aware) ----------
  // Historically named fmtINR / fmtINRShort; kept for API stability but now
  // render according to the user's Currency Format preference.
  function fmtINR(n) {
    if (!isFinite(n)) return '—';
    return currencySymbol() + Math.round(n).toLocaleString(currencyLocale());
  }
  function fmtINRShort(n) {
    if (!isFinite(n)) return '—';
    var v = Math.abs(n);
    var sym = currencySymbol();
    if (getCurrency() === 'western') {
      if (v >= 1e9) return sym + (n / 1e9).toFixed(2) + ' B';
      if (v >= 1e6) return sym + (n / 1e6).toFixed(2) + ' M';
      if (v >= 1e3) return sym + (n / 1e3).toFixed(1) + ' K';
      return fmtINR(n);
    }
    if (v >= 1e7) return sym + (n / 1e7).toFixed(2) + ' Cr';
    if (v >= 1e5) return sym + (n / 1e5).toFixed(2) + ' L';
    if (v >= 1e3) return sym + (n / 1e3).toFixed(1) + ' K';
    return fmtINR(n);
  }
  // Explicit aliases — prefer these in new code for clarity.
  var fmtMoney = fmtINR;
  var fmtMoneyShort = fmtINRShort;
  function fmtPct(n, d) { return (isFinite(n) ? n.toFixed(d == null ? 2 : d) : '—') + '%'; }

  // ---------- VALIDATORS ----------
  function guard(cond, msg) { if (!cond) throw new RangeError(msg); }
  function bound(v, lo, hi) { return v >= lo && v <= hi; }

  // ---------- CORE MATH ----------

  // SIP future value — annuity-due (contribution at START of each period)
  function sipFV(o) {
    guard(o.monthly > 0 && o.years > 0 && o.annualRatePct >= 0, 'Invalid SIP inputs');
    var n = Math.round(o.years * 12);
    var i = o.annualRatePct / 100 / 12;
    if (i === 0) return o.monthly * n;
    return o.monthly * ((Math.pow(1 + i, n) - 1) / i) * (1 + i);
  }

  // Reverse SIP — required monthly to reach a target future value
  function sipRequired(o) {
    guard(o.futureValue > 0 && o.years > 0 && o.annualRatePct >= 0, 'Invalid goal inputs');
    var n = Math.round(o.years * 12);
    var i = o.annualRatePct / 100 / 12;
    if (i === 0) return o.futureValue / n;
    return o.futureValue * i / (Math.pow(1 + i, n) - 1) / (1 + i);
  }

  // Lumpsum FV — annual compounding
  function lumpFV(o) {
    guard(o.principal > 0 && o.years > 0, 'Invalid lumpsum inputs');
    return o.principal * Math.pow(1 + o.annualRatePct / 100, o.years);
  }

  // Step-up SIP FV — each year's SIP grows by stepUpPct, compounded to horizon
  function stepUpSipFV(o) {
    guard(o.monthly > 0 && o.years > 0, 'Invalid step-up inputs');
    var i = o.annualRatePct / 100 / 12;
    var fv = 0;
    for (var y = 0; y < o.years; y++) {
      var thisMonthly = o.monthly * Math.pow(1 + o.stepUpPct / 100, y);
      var yearsLeft = o.years - y;
      var fvThisYear = (i === 0)
        ? thisMonthly * 12
        : thisMonthly * ((Math.pow(1 + i, 12) - 1) / i) * (1 + i);
      fv += fvThisYear * Math.pow(1 + o.annualRatePct / 100, yearsLeft - 1);
    }
    return fv;
  }

  // SWP — returns remaining corpus, months sustained, depletion flag, series
  function swp(o) {
    guard(o.corpus > 0 && o.monthlyWithdrawal > 0, 'Invalid SWP inputs');
    var i = o.annualRatePct / 100 / 12;
    var nMax = Math.round(o.years * 12);
    var balance = o.corpus, monthsSustained = 0, exhausted = false;
    var series = [];
    for (var m = 1; m <= nMax; m++) {
      balance = balance * (1 + i) - o.monthlyWithdrawal;
      if (balance <= 0) { monthsSustained = m; exhausted = true; series.push({ m: m, balance: 0 }); break; }
      series.push({ m: m, balance: balance });
      monthsSustained = m;
    }
    return { remaining: Math.max(balance, 0), monthsSustained: monthsSustained, exhaustedEarly: exhausted, series: series };
  }

  // Retirement — inflation-adjusted expense, required corpus, SIP to close gap
  function retirement(o) {
    var yToRet = o.retireAge - o.currentAge;
    var yInRet = o.lifeAge - o.retireAge;
    guard(yToRet > 0 && yInRet > 0, 'Age inputs invalid');
    var futureMonthlyExp = o.monthlyExpense * Math.pow(1 + o.inflationPct / 100, yToRet);
    var r = (o.postRetPct - o.inflationPct) / 100 / 12; // real monthly
    var n = yInRet * 12;
    var requiredCorpus = (r === 0)
      ? futureMonthlyExp * n
      : futureMonthlyExp * (1 - Math.pow(1 + r, -n)) / r;
    var savingsFV = (o.currentSavings && o.currentSavings > 0)
      ? lumpFV({ principal: o.currentSavings, years: yToRet, annualRatePct: o.preRetPct })
      : 0;
    var gap = Math.max(requiredCorpus - savingsFV, 0);
    var sip = gap === 0 ? 0 : sipRequired({ futureValue: gap, years: yToRet, annualRatePct: o.preRetPct });
    return { futureMonthlyExp: futureMonthlyExp, requiredCorpus: requiredCorpus, savingsFV: savingsFV, gap: gap, sip: sip };
  }

  // Cost of delay — how much you lose by starting N months later
  function costOfDelay(o) {
    var onTime  = sipFV({ monthly: o.monthly, years: o.years, annualRatePct: o.annualRatePct });
    var effYears = Math.max(o.years - (o.delayMonths / 12), 0.01);
    var delayed = sipFV({ monthly: o.monthly, years: effYears, annualRatePct: o.annualRatePct });
    return { onTime: onTime, delayed: delayed, cost: onTime - delayed };
  }

  // ---------- VALIDATION HELPERS ----------
  function validateSIP(inp) {
    var e = [];
    if (!(inp.monthly >= 500))                                e.push('Monthly SIP must be at least ₹500.');
    if (!bound(inp.years, 1, 40))                             e.push('Horizon must be between 1 and 40 years.');
    if (!bound(inp.annualRatePct, 1, 18))                     e.push('Return must be between 1% and 18% p.a. (equity MF historical range).');
    return e;
  }
  function validateLumpsum(inp) {
    var e = [];
    if (!(inp.principal >= 1000))                             e.push('Lumpsum must be at least ₹1,000.');
    if (!bound(inp.years, 1, 40))                             e.push('Horizon must be between 1 and 40 years.');
    if (!bound(inp.annualRatePct, 1, 18))                     e.push('Return must be between 1% and 18% p.a.');
    return e;
  }

  // ---------- THEME HELPERS (for charts) ----------
  function themeTokens() {
    var css = getComputedStyle(document.documentElement);
    var read = function (name) { return css.getPropertyValue(name).trim(); };
    return {
      text:    read('--text-1')    || '#141124',
      muted:   read('--text-3')    || '#6b6380',
      grid:    read('--border')    || '#e4dcc2',
      surface: read('--surface-1') || '#ffffff',
      palette: ['--c1','--c2','--c3','--c4','--c5'].map(read)
    };
  }
  function applyChartDefaults() {
    if (!global.Chart) return;
    var t = themeTokens();
    Chart.defaults.color = t.text;
    Chart.defaults.borderColor = t.grid;
    Chart.defaults.font.family = "'DM Sans', system-ui, sans-serif";
  }

  // ---------- DEBOUNCE (for slider inputs) ----------
  function debounce(fn, ms) {
    var t;
    return function () {
      var ctx = this, a = arguments;
      clearTimeout(t);
      t = setTimeout(function () { fn.apply(ctx, a); }, ms || 150);
    };
  }

  // ---------- SHARE HELPERS ----------
  function whatsappShare(text) {
    return 'https://wa.me/?text=' + encodeURIComponent(text);
  }
  function emailShare(subject, body) {
    return 'mailto:?subject=' + encodeURIComponent(subject) + '&body=' + encodeURIComponent(body);
  }

  // ---------- PUBLIC API ----------
  global.M3 = {
    fmtINR: fmtINR,
    fmtINRShort: fmtINRShort,
    fmtMoney: fmtMoney,
    fmtMoneyShort: fmtMoneyShort,
    getCurrency: getCurrency,
    setCurrency: setCurrency,
    currencySymbol: currencySymbol,
    currencyLocale: currencyLocale,
    fmtPct: fmtPct,
    sipFV: sipFV,
    sipRequired: sipRequired,
    lumpFV: lumpFV,
    stepUpSipFV: stepUpSipFV,
    swp: swp,
    retirement: retirement,
    costOfDelay: costOfDelay,
    validateSIP: validateSIP,
    validateLumpsum: validateLumpsum,
    themeTokens: themeTokens,
    applyChartDefaults: applyChartDefaults,
    debounce: debounce,
    whatsappShare: whatsappShare,
    emailShare: emailShare,
    // Constants
    RETURN_MAX: 18,
    RETURN_MIN: 1,
    RETURN_DEFAULT: 12
  };

  // Refresh chart defaults whenever theme flips
  if (typeof window !== 'undefined') {
    window.addEventListener('m3-theme-change', function () {
      applyChartDefaults();
      if (global.Chart && Chart.instances) {
        Object.keys(Chart.instances).forEach(function (k) { try { Chart.instances[k].update(); } catch (e) {} });
      }
    });
  }

  // ---------- FLOATING THEME TOGGLE ----------
  // Stand-alone pages (calculators, result, etc.) don't extend base.html
  // and therefore have no toggle. We auto-inject one ONLY if the page
  // lacks #m3ThemeToggle. Positioned bottom-right, doesn't overlap content.
  function injectFloatingToggle() {
    if (!document.body) return;
    if (document.getElementById('m3ThemeToggle')) return; // base.html already has one
    if (document.getElementById('m3FloatingTheme')) return; // already injected

    var btn = document.createElement('button');
    btn.id = 'm3FloatingTheme';
    btn.className = 'm3-theme-toggle';
    btn.type = 'button';
    btn.setAttribute('aria-label', 'Toggle light / dark theme');
    btn.setAttribute('title', 'Toggle theme');
    btn.innerHTML = '<span class="m3-sun" aria-hidden="true">☀︎</span>' +
                    '<span class="m3-moon" aria-hidden="true">☾</span>';
    btn.style.cssText = [
      'position:fixed', 'right:20px', 'bottom:20px', 'z-index:9999',
      'width:44px', 'height:44px', 'border-radius:50%',
      'background:var(--surface-2,#fdf9ee)', 'color:var(--text-1,#141124)',
      'border:1px solid var(--border,rgba(15,12,41,0.12))',
      'box-shadow:0 4px 14px rgba(15,12,41,.18)',
      'cursor:pointer', 'font-size:20px', 'line-height:1',
      'display:inline-flex', 'align-items:center', 'justify-content:center'
    ].join(';');

    var html = document.documentElement;
    var sunEl  = btn.querySelector('.m3-sun');
    var moonEl = btn.querySelector('.m3-moon');
    function sync() {
      // Resolve effective theme: explicit attr wins; else follow OS preference; else light.
      var attr = html.getAttribute('data-theme');
      var dark;
      if (attr === 'dark')      dark = true;
      else if (attr === 'light') dark = false;
      else dark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;

      btn.setAttribute('aria-pressed', dark ? 'true' : 'false');
      btn.setAttribute('title', dark ? 'Switch to light mode' : 'Switch to dark mode');
      document.body.classList.toggle('dark-mode', dark);

      // Show the icon that represents the CURRENT theme (sun = light, moon = dark).
      if (sunEl)  sunEl.style.display  = dark ? 'none' : 'inline';
      if (moonEl) moonEl.style.display = dark ? 'inline' : 'none';
    }
    btn.addEventListener('click', function () {
      var next = html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
      html.setAttribute('data-theme', next);
      try { localStorage.setItem('m3-theme', next); } catch (e) {}
      sync();
      window.dispatchEvent(new CustomEvent('m3-theme-change', { detail: next }));
    });
    sync();
    document.body.appendChild(btn);
  }

  if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', injectFloatingToggle);
    } else {
      injectFloatingToggle();
    }
  }
})(typeof window !== 'undefined' ? window : this);
