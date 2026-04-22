/* Meeting Mode bootstrap — runs on every page. */
(function () {
    var KEY = 'm3-meeting-mode';

    function isOn() {
        try { return localStorage.getItem(KEY) === '1'; } catch (e) { return false; }
    }
    function apply(on) {
        document.body.classList.toggle('meeting-mode', !!on);
        document.querySelectorAll('.mm-toggle').forEach(function (btn) {
            btn.setAttribute('aria-pressed', on ? 'true' : 'false');
            var label = btn.querySelector('.mm-label');
            if (label) label.textContent = on ? 'Meeting: ON' : 'Meeting Mode';
        });
        if (on) {
            try { document.documentElement.requestFullscreen && document.documentElement.requestFullscreen(); } catch (e) {}
        } else {
            try { document.fullscreenElement && document.exitFullscreen(); } catch (e) {}
        }
    }
    function toggle() {
        var next = !isOn();
        try { localStorage.setItem(KEY, next ? '1' : '0'); } catch (e) {}
        apply(next);
    }

    // Apply on load (must wait for body)
    function init() {
        apply(isOn());

        // Wire up all toggle buttons
        document.querySelectorAll('.mm-toggle').forEach(function (btn) {
            btn.addEventListener('click', toggle);
        });

        // Inject persistent exit pill (once)
        if (!document.getElementById('mm-exit-pill')) {
            var pill = document.createElement('button');
            pill.id = 'mm-exit-pill';
            pill.className = 'mm-exit-pill';
            pill.type = 'button';
            pill.innerHTML = '✕ Exit Meeting Mode';
            pill.addEventListener('click', toggle);
            document.body.appendChild(pill);
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    // Expose for other pages
    window.M3Meeting = { isOn: isOn, toggle: toggle };
})();
