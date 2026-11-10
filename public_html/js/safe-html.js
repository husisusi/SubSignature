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

    // Same intent as sanitizeTemplateHtml() on the server: no scripts, frames, plug-ins, forms,
    // foreign content (SVG / MathML) or raw-text elements whose parsing differs between browsers.
    var BLOCKED_TAGS = 'script,iframe,frame,frameset,object,embed,applet,form,input,textarea,select,option,optgroup,button,base,link,meta,' +
        'noscript,noembed,noframes,xmp,plaintext,template,title,svg,math,audio,video,source,track,canvas,portal,bgsound,isindex,keygen';
    var URL_ATTRS = ['href', 'src', 'xlink:href', 'action', 'formaction', 'background', 'poster'];

    function escapeHtml(value) {
        return String(value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    // Same allow-list as templateUrlIsSafe() on the server.
    var SAFE_SCHEMES = ['http', 'https', 'mailto', 'tel', 'sms', 'callto', 'cid', 'ftp', 'ftps', 'geo', 'skype', 'sip', 'sips',
        'facetime', 'facetime-audio', 'whatsapp', 'viber', 'tg', 'msteams', 'xmpp', 'webcal', 'maps'];

    function isSafeUrl(value) {
        // Strip whitespace/control characters that browsers ignore inside schemes.
        var v = String(value).replace(/[\u0000- \u007f-\u009f\u00ad\u200b-\u200f\u2028\u2029\ufeff]+/g, '').toLowerCase();
        var m = v.match(/^([a-z][a-z0-9+.\-]*):/);
        if (!m) {
            return true; // relative URL, fragment, placeholder
        }
        if (m[1] === 'data') {
            return /^data:image\/(png|gif|jpe?g|webp|bmp)[;,]/.test(v);
        }
        return SAFE_SCHEMES.indexOf(m[1]) !== -1;
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
                } else if (name === 'srcdoc') {
                    el.removeAttribute(attr.name);
                } else if (name === 'style' && /expression\s*\(|(?:java|vb)script\s*:|behaviou?r\s*:|-moz-binding|@import/i.test(attr.value.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\\/g, ''))) {
                    el.removeAttribute(attr.name);
                }
            });
        });

        // <style> blocks: no @import, expression(), behavior, script URLs and no "<".
        Array.prototype.forEach.call(doc.querySelectorAll('style'), function (st) {
            var css = String(st.textContent).replace(/<!--|-->|</g, '').replace(/@import\b[^;{}]*;?/gi, '');
            var probe = css.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\\/g, '');
            st.textContent = /expression\s*\(|(?:java|vb)script\s*:|behaviou?r\s*:|-moz-binding/i.test(probe) ? '' : css;
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
