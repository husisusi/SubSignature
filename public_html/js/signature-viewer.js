/**
 * signature-viewer.js - "Show all signatures" on All Signatures.
 *
 * Shows the signatures of the current list one at a time, like an image
 * viewer: arrows on both sides (and the arrow keys) go to the previous / next
 * signature. The preview button of a row opens the same viewer at that row.
 *
 * Security:
 *   - Signatures are fetched one by one from all_signatures.php?viewer=1, which
 *     applies the list's own scope, filters and sort order on the server.
 *   - The signature HTML is sanitised by the server, sanitised again here
 *     (SafeHtml.sanitize) and shown only in an iframe with an empty sandbox
 *     attribute: no scripts, no forms, no popups, an opaque origin.
 *   - Every other value (name, e-mail, tags, ...) is inserted with textContent,
 *     never as HTML; CSS class names are built only from allow-listed values.
 *   - Only a JSON answer is used. If the server answered with a redirect to
 *     the login page (session ended), a message is shown instead.
 *   - The endpoint is resolved against the page's own address and must stay
 *     on this origin.
 */
(function () {
    'use strict';

    var cfgEl = document.getElementById('sigViewerConfig');
    var overlay = document.getElementById('sigViewer');
    if (!cfgEl || !overlay || !window.SafeHtml || !window.fetch) {
        return;
    }
    var cfg;
    try {
        cfg = JSON.parse(cfgEl.textContent);
    } catch (e) {
        return;
    }
    var i18n = cfg.i18n || {};

    // Absolute endpoint on this origin; anything else disables the viewer.
    var endpoint;
    try {
        endpoint = new URL(String(cfg.endpoint || ''), window.location.href);
    } catch (e) {
        return;
    }
    if (endpoint.origin !== window.location.origin) {
        return;
    }

    var box = overlay.querySelector('.sv-box');
    var stage = document.getElementById('svStage');
    var frame = document.getElementById('svFrame');
    var counter = document.getElementById('svCounter');
    var errorEl = document.getElementById('svError');
    var nameEl = document.getElementById('svName');
    var ownerEl = document.getElementById('svOwner');
    var syncEl = document.getElementById('svSync');
    var tagsEl = document.getElementById('svTags');
    var metaEl = document.getElementById('svMeta');
    var downloadEl = document.getElementById('svDownload');
    var prevBtn = overlay.querySelector('[data-sv="prev"]');
    var nextBtn = overlay.querySelector('[data-sv="next"]');

    // Same base styles as the preview had before, so signatures look identical.
    var STYLE_RESET = '<style>' +
        'body { margin: 0; padding: 20px; font-family: Arial, Helvetica, sans-serif; background-color: #ffffff; color: #000000; }' +
        'p { margin: 0; padding: 0; line-height: 1.4; }' +
        'table { border-collapse: collapse; border-spacing: 0; }' +
        'td { padding: 0; vertical-align: top; }' +
        'a { text-decoration: none; color: inherit; }' +
        '</style>';

    var SYNC_LEVELS = ['grey', 'green', 'yellow', 'red'];
    var CACHE_MAX = 15;          // signatures kept in memory (current one and its neighbours)
    var WIDTH_KEY = 'subsig.viewer.width';

    var state = {
        open: false,
        pos: -1,                 // position of the shown signature in the list (0-based)
        total: toInt(cfg.total, 0),
        current: null,           // data of the shown signature
        cache: new Map(),        // pos -> data
        pending: new Map(),      // pos -> promise of a running request
        seq: 0,                  // only the newest request may update the view
        opener: null             // element that gets the focus back on close
    };

    function toInt(value, fallback) {
        var n = Number(value);
        return Number.isInteger(n) ? n : fallback;
    }

    function text(value) {
        return value === null || value === undefined ? '' : String(value);
    }

    function isRtl() {
        return (document.documentElement.getAttribute('dir') || '').toLowerCase() === 'rtl';
    }

    function ViewerError(kind, total) {
        this.kind = kind;
        this.total = total;
    }

    // Accepts only the fields and types the viewer uses.
    function normalise(d) {
        var id = toInt(d.id, 0);
        var pos = toInt(d.pos, -1);
        var total = toInt(d.total, -1);
        if (id <= 0 || pos < 0 || total < 1 || pos >= total) {
            throw new ViewerError('failed');
        }
        var tags = Array.isArray(d.tags) ? d.tags.slice(0, 50).map(function (t) {
            return { name: text(t && t.name), color: /^[a-z]{1,20}$/.test(text(t && t.color)) ? t.color : 'gray' };
        }) : [];
        var sync = (d.sync && typeof d.sync === 'object') ? d.sync : {};
        return {
            id: id, pos: pos, total: total,
            name: text(d.name), role: text(d.role), email: text(d.email), owner: text(d.owner),
            template: text(d.template), source: text(d.source), created: text(d.created),
            tags: tags,
            sync: sync,
            syncLevel: SYNC_LEVELS.indexOf(sync.level) !== -1 ? sync.level : 'grey',
            syncLabel: text(sync.label),
            html: text(d.html)
        };
    }

    // True when a request ended on the login page (index / index.php / site root).
    function landedOnLogin(r) {
        try {
            var url = new URL(r.url);
            return url.origin === window.location.origin && /(^|\/)(index(\.php)?)?$/.test(url.pathname);
        } catch (e) {
            return false;
        }
    }

    function fetchItem(query) {
        return fetch(endpoint.href + '&' + query, {
            credentials: 'same-origin',
            cache: 'no-store',
            headers: { 'Accept': 'application/json' }
        }).then(function (r) {
            var type = r.headers.get('Content-Type') || '';
            if (type.indexOf('application/json') !== 0) {
                // An HTML page instead of JSON: after a redirect to the login
                // page the session has ended, anything else is an error.
                throw new ViewerError(r.redirected && landedOnLogin(r) ? 'session' : 'failed');
            }
            return r.json().then(function (d) {
                if (r.status === 404 && d && typeof d === 'object') {
                    throw new ViewerError('gone', toInt(d.total, -1));
                }
                if (!r.ok || !d || typeof d !== 'object' || d.error) {
                    throw new ViewerError('failed');
                }
                return normalise(d);
            });
        }).catch(function (e) {
            throw (e instanceof ViewerError) ? e : new ViewerError('failed');
        });
    }

    function remember(d) {
        state.cache.delete(d.pos);
        state.cache.set(d.pos, d);
        while (state.cache.size > CACHE_MAX) {
            state.cache.delete(state.cache.keys().next().value);
        }
    }

    // Data of the signature at a position: from the cache, a running request or a new one.
    function itemAt(pos) {
        if (state.cache.has(pos)) {
            return Promise.resolve(state.cache.get(pos));
        }
        if (state.pending.has(pos)) {
            return state.pending.get(pos);
        }
        var p = fetchItem('pos=' + pos).then(function (d) {
            state.pending.delete(pos);
            remember(d);
            return d;
        }, function (e) {
            state.pending.delete(pos);
            throw e;
        });
        state.pending.set(pos, p);
        return p;
    }

    function prefetch(pos) {
        if (pos >= 0 && pos < state.total && !state.cache.has(pos)) {
            itemAt(pos).catch(function () { /* shown when the user gets there */ });
        }
    }

    function setLoading(on) {
        stage.classList.toggle('is-loading', on);
    }

    function updateCounter() {
        var label = '';
        if (state.pos >= 0 && state.total > 0) {
            label = text(i18n.counter || '{current} of {total}')
                .replace('{current}', String(state.pos + 1))
                .replace('{total}', String(state.total));
        }
        counter.textContent = label;
        counter.style.display = label ? '' : 'none';
    }

    function updateNav() {
        prevBtn.disabled = !(state.pos > 0);
        nextBtn.disabled = !(state.pos < state.total - 1);
        updateCounter();
    }

    function clearInfo() {
        nameEl.textContent = '';
        ownerEl.style.display = 'none';
        syncEl.style.display = 'none';
        tagsEl.textContent = '';
        metaEl.textContent = '';
        downloadEl.style.display = 'none';
        downloadEl.removeAttribute('href');
    }

    function render(d) {
        state.current = d;
        state.pos = d.pos;
        state.total = d.total;
        stage.classList.remove('has-error');
        errorEl.textContent = '';
        setLoading(false);

        frame.srcdoc = STYLE_RESET + window.SafeHtml.sanitize(d.html);

        nameEl.textContent = d.name;
        ownerEl.style.display = d.owner ? '' : 'none';
        ownerEl.lastElementChild.textContent = d.owner;

        syncEl.className = 'sync-badge sync-' + d.syncLevel;
        syncEl.lastElementChild.textContent = d.syncLabel;
        syncEl.style.display = d.syncLabel ? '' : 'none';

        tagsEl.textContent = '';
        d.tags.forEach(function (t) {
            var span = document.createElement('span');
            span.className = 'sig-tag tag-c-' + t.color;
            span.textContent = t.name;
            tagsEl.appendChild(span);
        });

        metaEl.textContent = [d.role, d.email, d.template, d.source, d.created]
            .filter(function (v) { return v !== ''; })
            .join(' \u2022 ');

        downloadEl.href = 'download.php?id=' + encodeURIComponent(String(d.id));
        downloadEl.style.display = '';

        updateNav();
        prefetch(d.pos + 1);
        prefetch(d.pos - 1);
    }

    function showError(e) {
        var kind = (e && e.kind) || 'failed';
        if (e && Number.isInteger(e.total) && e.total >= 0) {
            state.total = e.total;
        }
        state.current = null;
        clearInfo();
        frame.srcdoc = '';
        setLoading(false);
        errorEl.textContent = text(i18n[kind] || i18n.failed);
        stage.classList.add('has-error');
        updateNav();
    }

    // Shows the result of a request unless a newer one was started meanwhile.
    function show(promise) {
        var seq = ++state.seq;
        setLoading(true);
        promise.then(function (d) {
            if (seq === state.seq && state.open) {
                render(d);
            }
        }, function (e) {
            if (seq === state.seq && state.open) {
                showError(e);
            }
        });
    }

    function go(pos) {
        if (!state.open || pos < 0 || pos >= state.total) {
            return;
        }
        state.pos = pos;
        updateNav();
        show(itemAt(pos));
    }

    function applyWidth(mode) {
        var mobile = mode === 'mobile';
        box.classList.toggle('sv-mobile', mobile);
        overlay.querySelectorAll('.sv-width [data-sv]').forEach(function (b) {
            b.setAttribute('aria-pressed', String(b.getAttribute('data-sv') === (mobile ? 'mobile' : 'desktop')));
        });
    }

    function storedWidth() {
        try {
            return window.localStorage.getItem(WIDTH_KEY) === 'mobile' ? 'mobile' : 'desktop';
        } catch (e) {
            return 'desktop';
        }
    }

    function storeWidth(mode) {
        try {
            window.localStorage.setItem(WIDTH_KEY, mode);
        } catch (e) { /* storage may be blocked; the choice then lasts for this page only */ }
    }

    function openViewer(opener) {
        state.open = true;
        state.opener = opener || document.activeElement;
        state.cache.clear();
        state.pending.clear();
        state.pos = -1;
        state.current = null;
        clearInfo();
        stage.classList.remove('has-error');
        frame.srcdoc = '';
        applyWidth(storedWidth());
        overlay.style.display = 'flex';
        updateNav();
        nextBtn.focus();
    }

    function openAt(pos) {
        openViewer(document.activeElement);
        if (state.total < 1) {
            showError({ kind: 'empty' });
            return;
        }
        go(Math.max(0, Math.min(state.total - 1, toInt(pos, 0))));
    }

    function openById(id, opener) {
        id = toInt(id, 0);
        if (id <= 0) {
            return;
        }
        openViewer(opener);
        show(fetchItem('id=' + id).then(function (d) {
            remember(d);
            return d;
        }));
    }

    function close() {
        if (!state.open) {
            return;
        }
        state.open = false;
        state.seq++;             // ignore answers that are still on their way
        overlay.style.display = 'none';
        frame.srcdoc = '';
        setLoading(false);
        var back = state.opener;
        state.opener = null;
        if (back && typeof back.focus === 'function' && document.contains(back)) {
            back.focus();
        }
    }

    // True while another dialog (sync details) is shown above the viewer.
    function otherDialogOpen() {
        return Array.prototype.some.call(document.querySelectorAll('.modal-overlay'), function (m) {
            return m !== overlay && window.getComputedStyle(m).display !== 'none';
        });
    }

    function focusables() {
        return Array.prototype.filter.call(
            box.querySelectorAll('button, a[href], iframe'),
            function (el) { return !el.disabled && el.offsetParent !== null; }
        );
    }

    // ---- events ----------------------------------------------------------

    overlay.addEventListener('click', function (ev) {
        if (ev.target === overlay) {
            close();
            return;
        }
        var btn = ev.target.closest('[data-sv]');
        if (!btn || !overlay.contains(btn)) {
            return;
        }
        var action = btn.getAttribute('data-sv');
        if (action === 'close') {
            close();
        } else if (action === 'prev') {
            go(state.pos - 1);
        } else if (action === 'next') {
            go(state.pos + 1);
        } else if (action === 'desktop' || action === 'mobile') {
            applyWidth(action);
            storeWidth(action);
        } else if (action === 'sync' && state.current && typeof window.showSyncDetails === 'function') {
            window.showSyncDetails(state.current.sync);
        }
    });

    document.addEventListener('keydown', function (ev) {
        if (!state.open || otherDialogOpen() || ev.altKey || ev.ctrlKey || ev.metaKey) {
            return;
        }
        var back = isRtl() ? 'ArrowRight' : 'ArrowLeft';
        var forward = isRtl() ? 'ArrowLeft' : 'ArrowRight';
        if (ev.key === 'Escape') {
            ev.preventDefault();
            close();
        } else if (ev.key === back) {
            ev.preventDefault();
            go(state.pos - 1);
        } else if (ev.key === forward) {
            ev.preventDefault();
            go(state.pos + 1);
        } else if (ev.key === 'Home') {
            ev.preventDefault();
            go(0);
        } else if (ev.key === 'End') {
            ev.preventDefault();
            go(state.total - 1);
        } else if (ev.key === 'Tab') {
            // Keep the keyboard focus inside the dialog.
            var list = focusables();
            if (!list.length) {
                return;
            }
            var first = list[0];
            var last = list[list.length - 1];
            if (ev.shiftKey && (document.activeElement === first || !box.contains(document.activeElement))) {
                ev.preventDefault();
                last.focus();
            } else if (!ev.shiftKey && (document.activeElement === last || !box.contains(document.activeElement))) {
                ev.preventDefault();
                first.focus();
            }
        }
    });

    // Preview button of a row (rows are also added later by infinite scroll).
    document.addEventListener('click', function (ev) {
        var btn = ev.target.closest('[data-sv-open]');
        if (btn) {
            ev.preventDefault();
            openById(btn.getAttribute('data-sv-open'), btn);
        }
    });

    var showAll = document.getElementById('btnShowAll');
    if (showAll) {
        showAll.addEventListener('click', function () {
            openAt(0);
        });
    }

    window.SignatureViewer = { openAt: openAt, openById: openById, close: close };
})();
