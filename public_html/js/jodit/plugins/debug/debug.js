/*!
 * jodit - Jodit is an awesome and useful wysiwyg editor with filebrowser
 * Author: Chupurnov <chupurnov@gmail.com> (https://xdsoft.net/jodit/)
 * Version: v4.7.9
 * Url: https://xdsoft.net/jodit/
 * License(s): MIT
 */
	
"use strict";
(function webpackUniversalModuleDefinition(root, factory) {
	if(typeof exports === 'object' && typeof module === 'object')
		module.exports = factory();
	else if(typeof define === 'function' && define.amd)
		define([], factory);
	else {
		var a = factory();
		for(var i in a) (typeof exports === 'object' ? exports : root)[i] = a[i];
	}
})(self, function() {
return (self["webpackChunkjodit"] = self["webpackChunkjodit"] || []).push([[486],{

/***/ 96206:
/***/ (function(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   Debug: function() { return /* binding */ Debug; }
/* harmony export */ });
/* harmony import */ var jodit_core_constants__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(81937);
/* harmony import */ var jodit_core_dom_dom__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(23211);
/* harmony import */ var jodit_core_helpers_html_strip_tags__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(22852);
/* harmony import */ var jodit_core_plugin_plugin__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(18855);
/*!
 * Jodit Editor (https://xdsoft.net/jodit/)
 * Released under MIT see LICENSE.txt in the project root for license information.
 * Copyright (c) 2013-2025 Valeriy Chupurnov. All rights reserved. https://xdsoft.net
 */ /**
 * [[include:plugins/debug/README.md]]
 * @packageDocumentation
 * @module plugins/debug
 */ 




class Debug extends jodit_core_plugin_plugin__WEBPACK_IMPORTED_MODULE_3__.Plugin {
    afterInit(jodit) {
        const mirror = jodit.create.div('jodit-debug');
        const tree = jodit.create.div('jodit-debug__tree');
        const events = jodit.create.div('jodit-debug__events');
        const clear = jodit.create.div('jodit-debug__events-clear', [
            'x'
        ]);
        const sel = jodit.create.div('jodit-debug__sel');
        mirror.appendChild(tree);
        mirror.appendChild(events);
        events.appendChild(clear);
        mirror.appendChild(sel);
        clear.addEventListener('click', ()=>{
            events.innerHTML = '';
            events.appendChild(clear);
        });
        jodit.workplace.appendChild(mirror);
        const allEvents = [
            'activate',
            'afterInit',
            'beforeactivate',
            'beforeblur',
            'beforedeactivate',
            'beforefocus',
            'beforeinput',
            'blur',
            'change',
            'click',
            'compositionend',
            'compositionstart',
            'compositionupdate',
            'contextmenu',
            'copy',
            'cut',
            'dblclick',
            'deactivate',
            'focus',
            'focusin',
            'focusout',
            'focusout',
            'input',
            'keydown',
            'keypress',
            'keyup',
            'mousedown',
            'mouseup',
            'paste',
            'selectionchange',
            'selectionstart',
            'dragstart',
            'drop',
            'dragover',
            'resize touchstart touchend',
            'updateDebug',
            'beforeCommand',
            'afterCommand',
            'wheel'
        ];
        function updateTree() {
            const range = jodit.selection.range;
            tree.innerHTML = render(jodit.editor, 0, range);
            sel.innerHTML = `start ${range.startContainer.nodeName} ${range.startOffset}<br>end ${range.endContainer.nodeName} ${range.endOffset}`;
        }
        function onSomeEvent(e) {
            const event = jodit.e.current;
            const div = jodit.create.div();
            div.innerHTML = `<span>${new Date().toLocaleTimeString()}</span> ${renderEvent(event, e)}`;
            events.appendChild(div);
            events.scrollTop = events.scrollHeight;
            jodit.async.setTimeout(()=>{
                events.children.length > 100 && events.removeChild(events.children[0]);
            }, 100);
        }
        function renderEvent(event, e) {
            const result = [
                event ?? e.type
            ];
            switch(event){
                case 'beforeCommand':
                case 'afterCommand':
                    result.push(`<span>${e.toString()}</span>`);
                    break;
                case 'keydown':
                case 'keyup':
                case 'keypress':
                    if (e.shiftKey && e.key !== 'Shift') {
                        result.push('Shift+');
                    }
                    if (e.ctrlKey && e.key !== 'Control') {
                        result.push('Ctrl+');
                    }
                    if (e.altKey && e.key !== 'Alt') {
                        result.push('Alt');
                    }
                    result.push(`${e.key}`);
                    break;
            }
            if (e && jodit_core_dom_dom__WEBPACK_IMPORTED_MODULE_1__.Dom.isNode(e.target)) {
                result.push(`<span>${e.target.nodeName}</span>`);
            }
            return result.join(' ');
        }
        jodit.e.on('keydown keyup keypress change afterInit updateDebug', updateTree).on(allEvents, onSomeEvent).on(jodit.od, 'selectionchange', onSomeEvent).on(jodit.od, 'selectionchange', updateTree);
    }
    beforeDestruct(jodit) {}
}
function renderText(elm, range) {
    if (!elm.nodeValue) {
        return "<span style='color:red'>empty</span>";
    }
    let value = elm.nodeValue;
    if (range.collapsed) {
        if (elm === range.startContainer) {
            value = value.slice(0, range.startOffset) + '%CURSOR%' + value.slice(range.startOffset);
        }
    } else {
        if (elm === range.startContainer && elm === range.endContainer) {
            value = value.slice(0, range.startOffset) + '%START-CURSOR%' + value.slice(range.startOffset, range.endOffset) + '%END-CURSOR%' + value.slice(range.endOffset);
        } else if (elm === range.startContainer) {
            value = value.slice(0, range.startOffset) + '%CURSOR%' + value.slice(range.startOffset);
        } else if (elm === range.endContainer) {
            value = value.slice(0, range.endOffset) + '%CURSOR%' + value.slice(range.endOffset);
        }
    }
    return (0,jodit_core_helpers_html_strip_tags__WEBPACK_IMPORTED_MODULE_2__.stripTags)(value.replace((0,jodit_core_constants__WEBPACK_IMPORTED_MODULE_0__.INVISIBLE_SPACE_REG_EXP)(), 'INV')).replace(/%CURSOR%/, '<span class="jodit-debug__tree-cursor">|</span>').replace(/%START-CURSOR%/, '<span class="jodit-debug__tree-cursor">|').replace(/%END-CURSOR%/, '|</span>');
}
function render(elm, level, range) {
    const isSelected = window.getSelection()?.containsNode(elm);
    const content = [
        `<span class="jodit-debug__tree-elm-name">${elm.nodeName}</span>`,
        jodit_core_dom_dom__WEBPACK_IMPORTED_MODULE_1__.Dom.isText(elm) ? `- ${renderText(elm, range)}` : ''
    ].map((i)=>i.trim()).filter(Boolean);
    return `<div class="${isSelected ? 'jodit-debug__tree-element_selected' : ''}" style='padding-left: ${level * 5}px'>
		${content.join('&nbsp;')}
	${Array.from(elm.childNodes).map((ch, index)=>{
        const result = [];
        if (range.startContainer === elm && index === range.startOffset) {
            result.push('<span class="jodit-debug__tree-cursor">|</span>');
        }
        result.push(render(ch, level + 1, range));
        if (range.endContainer === elm && index === range.endOffset) {
            result.push('<span class="jodit-debug__tree-cursor">|</span>');
        }
        return result;
    }).flat().join('')}
</div>`;
} // pluginSystem.add('debug', Debug);


/***/ })

},
/******/ function(__webpack_require__) { // webpackRuntimeModules
/******/ var __webpack_exec__ = function(moduleId) { return __webpack_require__(__webpack_require__.s = moduleId); }
/******/ var __webpack_exports__ = (__webpack_exec__(96206));
/******/ return __webpack_exports__;
/******/ }
]);
});