/**
 * post-action.js
 *
 * State-changing actions (delete, activate, ...) must never be plain links.
 * Any element with a data-post attribute submits a POST request including the
 * CSRF token from <meta name="csrf-token">.
 *
 *   <button data-post="generate.php"
 *           data-params='{"action":"delete","id":"12"}'
 *           data-confirm="Delete this signature?">Delete</button>
 */
(function () {
    'use strict';

    document.addEventListener('click', function (event) {
        var trigger = event.target.closest('[data-post]');
        if (!trigger) {
            return;
        }
        event.preventDefault();

        var message = trigger.getAttribute('data-confirm');
        if (message && !window.confirm(message)) {
            return;
        }

        var meta = document.querySelector('meta[name="csrf-token"]');
        var params = {};
        try {
            params = JSON.parse(trigger.getAttribute('data-params') || '{}');
        } catch (e) {
            return; // malformed parameters: do nothing
        }

        var form = document.createElement('form');
        form.method = 'POST';
        form.action = trigger.getAttribute('data-post');
        form.style.display = 'none';

        function addField(name, value) {
            var input = document.createElement('input');
            input.type = 'hidden';
            input.name = name;
            input.value = String(value);
            form.appendChild(input);
        }

        Object.keys(params).forEach(function (key) {
            addField(key, params[key]);
        });
        addField('csrf_token', meta ? meta.getAttribute('content') : '');

        document.body.appendChild(form);
        form.submit();
    });
})();
