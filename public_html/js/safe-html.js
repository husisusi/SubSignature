/**
 * safe-html.js
 *
 * Small client-side helpers used by the live preview. Template HTML and user
 * input are never inserted into the page without going through these.
 *
 *   SafeHtml.escape(text)            -> HTML-escaped text
 *   SafeHtml.fill(template, values)  -> template with {{PLACEHOLDERS}} replaced by escaped values
 *   (NAME ROLE EMAIL PHONE PHONE_CLEAN and the company-wide COMPANY WEBSITE ADDRESS DISCLAIMER)
 *   SafeHtml.sanitize(html)          -> HTML without scripts, event handlers or script URLs
 */
(function (global) {
    'use strict';

    var BLOCKED_TAGS = 'script,iframe,frame,frameset,object,embed,applet,form,input,textarea,select,button,base,link,meta,noscript';
    var URL_ATTRS = ['href', 'src', 'xlink:href', 'action', 'formaction', 'background', 'poster'];

    function escapeHtml(value) {
        return String(value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    function isSafeUrl(value) {
        // Strip whitespace/control characters that browsers ignore inside schemes.
        var v = String(value).replace(/[\u0000- \u007f-\u009f]+/g, '').toLowerCase();
        if (/^(javascript|vbscript):/.test(v)) {
            return false;
        }
        if (/^data:/.test(v) && !/^data:image\/(png|gif|jpe?g|webp|bmp);/.test(v)) {
            return false;
        }
        return true;
    }

    function sanitize(html) {
        var doc = new DOMParser().parseFromString(String(html), 'text/html');

        Array.prototype.forEach.call(doc.querySelectorAll(BLOCKED_TAGS), function (node) {
            node.parentNode.removeChild(node);
        });

        Array.prototype.forEach.call(doc.body.querySelectorAll('*'), function (el) {
            Array.prototype.slice.call(el.attributes).forEach(function (attr) {
                var name = attr.name.toLowerCase();
                if (name.indexOf('on') === 0) {
                    el.removeAttribute(attr.name);
                } else if (URL_ATTRS.indexOf(name) !== -1 && !isSafeUrl(attr.value)) {
                    el.removeAttribute(attr.name);
                } else if (name === 'style' && /expression\s*\(|javascript:|behavior\s*:/i.test(attr.value)) {
                    el.removeAttribute(attr.name);
                }
            });
        });

        // <style> blocks of the template survive in <head> after parsing; keep them.
        var styles = '';
        Array.prototype.forEach.call(doc.head.querySelectorAll('style'), function (s) {
            styles += s.outerHTML;
        });
        return styles + doc.body.innerHTML;
    }

    function fill(template, values) {
        // One pass with a replacer function: values containing "$&" or
        // "{{EMAIL}}" are inserted literally and never expanded again.
        return String(template).replace(/\{\{(NAME|ROLE|EMAIL|PHONE_CLEAN|PHONE|COMPANY|WEBSITE|ADDRESS|DISCLAIMER)\}\}/g, function (match, key) {
            var v = escapeHtml(values[key] === undefined ? '' : values[key]);
            // Multi-line company texts keep their line breaks.
            return (key === 'ADDRESS' || key === 'DISCLAIMER') ? v.replace(/\r?\n/g, '<br>') : v;
        });
    }

    global.SafeHtml = { escape: escapeHtml, fill: fill, sanitize: sanitize };
})(window);
