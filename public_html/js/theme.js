/**
 * theme.js - light / dark / system colour theme.
 *
 * Loaded synchronously in <head> (before the stylesheets) so the right palette
 * is applied before the first paint. The choice is stored in localStorage
 * (per browser); "system" follows the operating system setting live.
 *
 * Other scripts can listen to the "subsig-theme-change" event
 * (event.detail.theme is "light" or "dark") and read window.SubSigTheme.
 */
(function () {
    'use strict';

    var STORAGE_KEY = 'subsig-theme';
    var MODES = ['light', 'dark', 'system'];
    var root = document.documentElement;
    var media = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null;

    function readPreference() {
        try {
            var stored = window.localStorage.getItem(STORAGE_KEY);
            if (MODES.indexOf(stored) !== -1) {
                return stored;
            }
        } catch (e) { /* storage blocked: fall back to the system setting */ }
        return 'system';
    }

    function resolve(pref) {
        if (pref === 'system') {
            return media && media.matches ? 'dark' : 'light';
        }
        return pref;
    }

    var preference = readPreference();

    function apply() {
        var theme = resolve(preference);
        root.setAttribute('data-theme', theme);
        root.setAttribute('data-theme-pref', preference);
        updateButtons();
        try {
            document.dispatchEvent(new CustomEvent('subsig-theme-change', { detail: { theme: theme, preference: preference } }));
        } catch (e) { /* very old browsers: ignore */ }
    }

    function setPreference(pref) {
        if (MODES.indexOf(pref) === -1) { return; }
        preference = pref;
        try { window.localStorage.setItem(STORAGE_KEY, pref); } catch (e) { /* ignore */ }
        apply();
    }

    // ------------------------------------------------------------------
    // Switch UI (built with DOM methods only, no HTML strings)
    // ------------------------------------------------------------------
    var LABELS = {
        light:  { icon: 'fa-sun',     text: 'Light' },
        dark:   { icon: 'fa-moon',    text: 'Dark' },
        system: { icon: 'fa-desktop', text: 'Follow system setting' }
    };
    var buttons = [];

    function updateButtons() {
        buttons.forEach(function (btn) {
            btn.setAttribute('aria-pressed', btn.getAttribute('data-mode') === preference ? 'true' : 'false');
        });
    }

    function buildSwitch(floating) {
        var wrap = document.createElement('div');
        wrap.className = 'theme-switch' + (floating ? ' floating' : '');
        wrap.setAttribute('role', 'group');
        wrap.setAttribute('aria-label', 'Colour theme');

        MODES.forEach(function (mode) {
            var btn = document.createElement('button');
            btn.type = 'button';
            btn.setAttribute('data-mode', mode);
            btn.setAttribute('title', LABELS[mode].text);
            btn.setAttribute('aria-label', LABELS[mode].text);
            var icon = document.createElement('i');
            icon.className = 'fas ' + LABELS[mode].icon;
            btn.appendChild(icon);
            btn.addEventListener('click', function () { setPreference(mode); });
            wrap.appendChild(btn);
            buttons.push(btn);
        });
        return wrap;
    }

    function mountSwitch() {
        var footer = document.querySelector('.sidebar-footer');
        if (footer) {
            footer.insertBefore(buildSwitch(false), footer.firstChild);
        } else {
            document.body.appendChild(buildSwitch(true));
        }
        updateButtons();
    }

    // Follow the operating system while "system" is selected.
    if (media) {
        var onSystemChange = function () { if (preference === 'system') { apply(); } };
        if (media.addEventListener) { media.addEventListener('change', onSystemChange); }
        else if (media.addListener) { media.addListener(onSystemChange); }
    }

    // Keep several open tabs in sync.
    window.addEventListener('storage', function (event) {
        if (event.key === STORAGE_KEY) {
            preference = readPreference();
            apply();
        }
    });

    apply();

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', mountSwitch);
    } else {
        mountSwitch();
    }

    window.SubSigTheme = {
        get: function () { return resolve(preference); },
        getPreference: function () { return preference; },
        set: setPreference
    };
})();
