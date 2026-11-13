// js/alerts.js - status messages created in the browser.
//
// SubSigAlert.show(type, text) shows the same message box as the server-side
// alertBox() helper (types: success, error, warning, info) at the top of the
// page, instead of a browser alert() popup. The text is always inserted as
// plain text (textContent), never as HTML.
(function () {
    'use strict';

    var ICONS = {
        success: 'check-circle',
        error: 'exclamation-circle',
        warning: 'exclamation-triangle',
        info: 'info-circle'
    };

    // Where the message goes: an element marked with data-alert-host, else
    // right below the page header of the main content, else the top of <body>.
    function place(box) {
        var host = document.querySelector('[data-alert-host]');
        if (host) {
            host.insertBefore(box, host.firstChild);
            return;
        }
        var main = document.querySelector('.main-content');
        if (main) {
            var header = main.querySelector('.page-header');
            if (header && header.parentNode === main) {
                main.insertBefore(box, header.nextSibling);
            } else {
                main.insertBefore(box, main.firstChild);
            }
            return;
        }
        document.body.insertBefore(box, document.body.firstChild);
    }

    function show(type, text) {
        if (!Object.prototype.hasOwnProperty.call(ICONS, type)) {
            type = 'info';
        }
        // Only one browser-side message at a time.
        var old = document.querySelectorAll('.alert-dynamic');
        for (var i = 0; i < old.length; i++) {
            old[i].parentNode.removeChild(old[i]);
        }

        var box = document.createElement('div');
        box.className = 'alert alert-' + type + ' alert-dynamic';
        box.setAttribute('role', (type === 'error' || type === 'warning') ? 'alert' : 'status');

        var icon = document.createElement('i');
        icon.className = 'fas fa-' + ICONS[type];
        icon.setAttribute('aria-hidden', 'true');

        var body = document.createElement('div');
        body.className = 'alert-text';
        body.textContent = String(text);

        box.appendChild(icon);
        box.appendChild(body);
        place(box);
        if (box.scrollIntoView) {
            box.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
        return box;
    }

    window.SubSigAlert = { show: show };
})();
