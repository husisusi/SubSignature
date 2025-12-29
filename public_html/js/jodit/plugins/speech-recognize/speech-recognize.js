/*!
 * jodit - Jodit is an awesome and useful wysiwyg editor with filebrowser
 * Author: Chupurnov <chupurnov@gmail.com> (https://xdsoft.net/jodit/)
 * Version: v4.7.9
 * Url: https://xdsoft.net/jodit/
 * License(s): MIT
 */
	
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
return (self["webpackChunkjodit"] = self["webpackChunkjodit"] || []).push([[882],{

/***/ 22227:
/***/ (function(module) {

module.exports = "<svg viewBox=\"0 0 16 16\" xml:space=\"preserve\" xmlns=\"http://www.w3.org/2000/svg\"> <path d=\"M8,11c1.657,0,3-1.343,3-3V3c0-1.657-1.343-3-3-3S5,1.343,5,3v5C5,9.657,6.343,11,8,11z\"/> <path d=\"M13,8V6h-1l0,1.844c0,1.92-1.282,3.688-3.164,4.071C6.266,12.438,4,10.479,4,8V6H3v2c0,2.414,1.721,4.434,4,4.899V15H5v1h6 v-1H9v-2.101C11.279,12.434,13,10.414,13,8z\"/> </svg>"

/***/ }),

/***/ 31262:
/***/ (function(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   SpeechRecognizeNative: function() { return /* binding */ SpeechRecognizeNative; }
/* harmony export */ });
/* harmony import */ var _swc_helpers_define_property__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(25045);
/* harmony import */ var _swc_helpers_ts_decorate__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(31635);
/* harmony import */ var jodit_core_decorators_watch_watch__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(68616);
/* harmony import */ var jodit_core_dom_dom__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(23211);
/* harmony import */ var jodit_core_global__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(28077);
/* harmony import */ var jodit_core_helpers_utils_utils__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(71125);
/* harmony import */ var jodit_core_plugin__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(91206);
/* harmony import */ var _config__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(75143);
/* harmony import */ var _jodit__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(73302);
/* harmony import */ var _helpers_exec_spell_command__WEBPACK_IMPORTED_MODULE_9__ = __webpack_require__(86581);
/* harmony import */ var _langs__WEBPACK_IMPORTED_MODULE_10__ = __webpack_require__(43219);
/*!
 * Jodit Editor (https://xdsoft.net/jodit/)
 * Released under MIT see LICENSE.txt in the project root for license information.
 * Copyright (c) 2013-2025 Valeriy Chupurnov. All rights reserved. https://xdsoft.net
 */ /**
 * [[include:plugins/speech-recognize/README.md]]
 * @packageDocumentation
 * @module plugins/speech-recognize
 */ 











class SpeechRecognizeNative extends jodit_core_plugin__WEBPACK_IMPORTED_MODULE_6__.Plugin {
    afterInit(jodit) {
        const { commands } = jodit.o.speechRecognize;
        if (commands) {
            (0,jodit_core_global__WEBPACK_IMPORTED_MODULE_4__.extendLang)(_langs__WEBPACK_IMPORTED_MODULE_10__);
            (0,jodit_core_helpers_utils_utils__WEBPACK_IMPORTED_MODULE_5__.keys)(commands, false).forEach((words)=>{
                const keys = words.split('|');
                keys.forEach((key)=>{
                    key = key.trim().toLowerCase();
                    this._commandToWord[key] = commands[words];
                    const translatedKeys = jodit.i18n(key);
                    if (translatedKeys !== key) {
                        translatedKeys.split('|').forEach((translatedKey)=>{
                            this._commandToWord[translatedKey.trim().toLowerCase()] = commands[words].trim();
                        });
                    }
                });
            });
        }
    }
    beforeDestruct(jodit) {
        jodit_core_dom_dom__WEBPACK_IMPORTED_MODULE_3__.Dom.safeRemove(this.messagePopup);
    }
    onSpeechRecognizeProgressResult(text) {
        if (!this.messagePopup) {
            this.messagePopup = this.j.create.div('jodit-speech-recognize__popup');
        }
        this.j.workplace.appendChild(this.messagePopup);
        this.j.async.clearTimeout(this.__hidePopupTimeout);
        this.__hidePopupTimeout = this.j.async.setTimeout(()=>{
            jodit_core_dom_dom__WEBPACK_IMPORTED_MODULE_3__.Dom.safeRemove(this.messagePopup);
        }, 1000);
        this.messagePopup.innerText = text + '|';
    }
    onSpeechRecognizeResult(text) {
        this.j.async.clearTimeout(this.__hidePopupTimeout);
        jodit_core_dom_dom__WEBPACK_IMPORTED_MODULE_3__.Dom.safeRemove(this.messagePopup);
        const { j } = this;
        const { s } = j;
        if (!this._checkCommand(text)) {
            const { range } = s, node = s.current();
            if (s.isCollapsed() && jodit_core_dom_dom__WEBPACK_IMPORTED_MODULE_3__.Dom.isText(node) && jodit_core_dom_dom__WEBPACK_IMPORTED_MODULE_3__.Dom.isOrContains(j.editor, node) && node.nodeValue) {
                const sentence = node.nodeValue;
                node.nodeValue = sentence + (/[\u00A0 ]\uFEFF*$/.test(sentence) ? '' : ' ') + text;
                range.setStartAfter(node);
                s.selectRange(range);
                j.synchronizeValues();
            } else {
                s.insertHTML(text);
            }
        }
    }
    _checkCommand(command) {
        command = command.toLowerCase().replace(/\./g, '');
        if (this._commandToWord[command]) {
            (0,_helpers_exec_spell_command__WEBPACK_IMPORTED_MODULE_9__.execSpellCommand)(this.j, this._commandToWord[command]);
            return true;
        }
        return false;
    }
    constructor(...args){
        super(...args), (0,_swc_helpers_define_property__WEBPACK_IMPORTED_MODULE_0__._)(this, "buttons", [
            {
                group: 'state',
                name: 'speechRecognize'
            }
        ]), (0,_swc_helpers_define_property__WEBPACK_IMPORTED_MODULE_0__._)(this, "messagePopup", void 0), (0,_swc_helpers_define_property__WEBPACK_IMPORTED_MODULE_0__._)(this, "__hidePopupTimeout", void 0), (0,_swc_helpers_define_property__WEBPACK_IMPORTED_MODULE_0__._)(this, "_commandToWord", {});
    }
}
(0,_swc_helpers_ts_decorate__WEBPACK_IMPORTED_MODULE_1__.__decorate)([
    (0,jodit_core_decorators_watch_watch__WEBPACK_IMPORTED_MODULE_2__.watch)(':speechRecognizeProgressResult')
], SpeechRecognizeNative.prototype, "onSpeechRecognizeProgressResult", null);
(0,_swc_helpers_ts_decorate__WEBPACK_IMPORTED_MODULE_1__.__decorate)([
    (0,jodit_core_decorators_watch_watch__WEBPACK_IMPORTED_MODULE_2__.watch)(':speechRecognizeResult')
], SpeechRecognizeNative.prototype, "onSpeechRecognizeResult", null);
_jodit__WEBPACK_IMPORTED_MODULE_8__.Jodit.plugins.add('speech-recognize', SpeechRecognizeNative);


/***/ }),

/***/ 32560:
/***/ (function(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

"use strict";
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   sound: function() { return /* binding */ sound; }
/* harmony export */ });
/* harmony import */ var jodit_core_constants__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(81937);
/* harmony import */ var jodit_plugins_speech_recognize_constants__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(94092);
/*!
 * Jodit Editor (https://xdsoft.net/jodit/)
 * Released under MIT see LICENSE.txt in the project root for license information.
 * Copyright (c) 2013-2025 Valeriy Chupurnov. All rights reserved. https://xdsoft.net
 */ /**
 * @module plugins/speech-recognize
 */ 

/**
 * @internal
 */ function sound({ sec = 0.1, frequency = jodit_plugins_speech_recognize_constants__WEBPACK_IMPORTED_MODULE_1__.PII, gain = 0.1, type = 'sine' } = {}) {
    if (!jodit_core_constants__WEBPACK_IMPORTED_MODULE_0__.globalWindow || typeof jodit_core_constants__WEBPACK_IMPORTED_MODULE_0__.globalWindow.AudioContext === 'undefined' && typeof jodit_core_constants__WEBPACK_IMPORTED_MODULE_0__.globalWindow.webkitAudioContext === 'undefined') {
        return;
    }
    // one context per document
    const context = new (jodit_core_constants__WEBPACK_IMPORTED_MODULE_0__.globalWindow.AudioContext || jodit_core_constants__WEBPACK_IMPORTED_MODULE_0__.globalWindow.webkitAudioContext)();
    const vol = context.createGain();
    const osc = context.createOscillator();
    osc.type = type;
    osc.frequency.value = frequency; // Hz
    osc.connect(vol);
    vol.connect(context.destination);
    osc.start(); // start the oscillator
    osc.stop(context.currentTime + sec);
    vol.gain.value = gain;
}


/***/ }),

/***/ 43219:
/***/ (function(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   ar: function() { return /* reexport module object */ _ar_js__WEBPACK_IMPORTED_MODULE_0__; },
/* harmony export */   cs_cz: function() { return /* reexport module object */ _ar_js__WEBPACK_IMPORTED_MODULE_0__; },
/* harmony export */   de: function() { return /* reexport module object */ _ar_js__WEBPACK_IMPORTED_MODULE_0__; },
/* harmony export */   es: function() { return /* reexport module object */ _ar_js__WEBPACK_IMPORTED_MODULE_0__; },
/* harmony export */   fa: function() { return /* reexport module object */ _ar_js__WEBPACK_IMPORTED_MODULE_0__; },
/* harmony export */   fi: function() { return /* reexport module object */ _ar_js__WEBPACK_IMPORTED_MODULE_0__; },
/* harmony export */   fr: function() { return /* reexport module object */ _ar_js__WEBPACK_IMPORTED_MODULE_0__; },
/* harmony export */   he: function() { return /* reexport module object */ _ar_js__WEBPACK_IMPORTED_MODULE_0__; },
/* harmony export */   hu: function() { return /* reexport module object */ _ar_js__WEBPACK_IMPORTED_MODULE_0__; },
/* harmony export */   id: function() { return /* reexport module object */ _ar_js__WEBPACK_IMPORTED_MODULE_0__; },
/* harmony export */   it: function() { return /* reexport module object */ _ar_js__WEBPACK_IMPORTED_MODULE_0__; },
/* harmony export */   ja: function() { return /* reexport module object */ _ar_js__WEBPACK_IMPORTED_MODULE_0__; },
/* harmony export */   ko: function() { return /* reexport module object */ _ar_js__WEBPACK_IMPORTED_MODULE_0__; },
/* harmony export */   mn: function() { return /* reexport module object */ _ar_js__WEBPACK_IMPORTED_MODULE_0__; },
/* harmony export */   nl: function() { return /* reexport module object */ _ar_js__WEBPACK_IMPORTED_MODULE_0__; },
/* harmony export */   no: function() { return /* reexport module object */ _ar_js__WEBPACK_IMPORTED_MODULE_0__; },
/* harmony export */   pl: function() { return /* reexport module object */ _ar_js__WEBPACK_IMPORTED_MODULE_0__; },
/* harmony export */   pt_br: function() { return /* reexport module object */ _ar_js__WEBPACK_IMPORTED_MODULE_0__; },
/* harmony export */   ru: function() { return /* reexport module object */ _ar_js__WEBPACK_IMPORTED_MODULE_0__; },
/* harmony export */   tr: function() { return /* reexport module object */ _ar_js__WEBPACK_IMPORTED_MODULE_0__; },
/* harmony export */   ua: function() { return /* reexport module object */ _ar_js__WEBPACK_IMPORTED_MODULE_0__; },
/* harmony export */   zh_cn: function() { return /* reexport module object */ _ar_js__WEBPACK_IMPORTED_MODULE_0__; },
/* harmony export */   zh_tw: function() { return /* reexport module object */ _ar_js__WEBPACK_IMPORTED_MODULE_0__; }
/* harmony export */ });
/* harmony import */ var _ar_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(41324);
/* harmony import */ var _ar_js__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(_ar_js__WEBPACK_IMPORTED_MODULE_0__);
/*!
 * Jodit Editor (https://xdsoft.net/jodit/)
 * Released under MIT see LICENSE.txt in the project root for license information.
 * Copyright (c) 2013-2025 Valeriy Chupurnov. All rights reserved. https://xdsoft.net
 */ // @ts-nocheck


























/***/ }),

/***/ 68097:
/***/ (function(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

"use strict";
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   RecognizeManager: function() { return /* binding */ RecognizeManager; }
/* harmony export */ });
/* harmony import */ var _swc_helpers_define_property__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(25045);
/* harmony import */ var _swc_helpers_ts_decorate__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(31635);
/* harmony import */ var jodit_core_decorators__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(84839);
/* harmony import */ var jodit_core_event_emitter_eventify__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(60216);
/* harmony import */ var _sound__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(32560);
/* harmony import */ var jodit_plugins_speech_recognize_constants__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(94092);
/*!
 * Jodit Editor (https://xdsoft.net/jodit/)
 * Released under MIT see LICENSE.txt in the project root for license information.
 * Copyright (c) 2013-2025 Valeriy Chupurnov. All rights reserved. https://xdsoft.net
 */ /**
 * @module plugins/speech-recognize
 */ 





class RecognizeManager extends jodit_core_event_emitter_eventify__WEBPACK_IMPORTED_MODULE_3__.Eventify {
    set lang(v) {
        this._lang = v;
        this._api.lang = v;
    }
    get lang() {
        return this._lang;
    }
    set continuous(v) {
        this._continuous = v;
        this._api.continuous = v;
    }
    get continuous() {
        return this._continuous;
    }
    set interimResults(v) {
        this._interimResults = v;
        this._api.interimResults = v;
    }
    get interimResults() {
        return this._interimResults;
    }
    destruct() {
        this.stop();
        RecognizeManager._instances.delete(this);
        super.destruct();
    }
    get isEnabled() {
        return this._isEnabled;
    }
    start() {
        if (this._isEnabled) {
            return;
        }
        this._isEnabled = true;
        RecognizeManager._instances.forEach((instance)=>{
            if (instance !== this) {
                instance.stop();
            }
        });
        try {
            this._api.start();
        } catch (e) {
            this._onError(e);
            this.stop();
            return;
        }
        this.__on('speechstart', this._onSpeechStart).__on('error', this._onError).__on('result', this._onProgress).__on('end', this._onResults);
    }
    stop() {
        if (!this._isEnabled) {
            return;
        }
        this._api.abort();
        this._api.stop();
        this.__off('speechstart', this._onSpeechStart).__off('error', this._onError).__off('result', this._onProgress).__off('end', this._onResults);
        this.async.clearTimeout(this._restartTimeout);
        this._isEnabled = false;
        this.emit('pulse', false);
    }
    toggle() {
        if (!this._isEnabled) {
            this.start();
        } else {
            this.stop();
        }
    }
    restart() {
        this.stop();
        this.start();
    }
    __on(event, callback) {
        this._api.addEventListener(event, callback);
        return this;
    }
    __off(event, callback) {
        this._api.removeEventListener(event, callback);
        return this;
    }
    _onResults(e) {
        this.emit('pulse', false);
        this.emit('result', this.__interimResults);
        this.__interimResults = '';
        this._makeSound(jodit_plugins_speech_recognize_constants__WEBPACK_IMPORTED_MODULE_5__.PII);
        this.restart();
    }
    _onProgress(e) {
        if (!this._isEnabled) {
            return;
        }
        this.__interimResults = '';
        if (!e.results) {
            return;
        }
        for(let i = 0; i < e.results.length; i++){
            const resultItem = e.results.item(i);
            if (resultItem.length) {
                const { transcript } = resultItem.item(0);
                this.__interimResults += transcript;
            }
        }
        if (this.__interimResults) {
            this.emit('progress', this.__interimResults);
        }
    }
    _onError(e) {
        if (e.error === 'voice-unavailable') {
            this.emit('error', 'Voice unavailable');
        }
        if (e.error === 'not-allowed') {
            this.emit('error', 'Not allowed');
        }
        if (e.error === 'language-unavailable' || // @ts-ignore
        e.error === 'language-not-supported') {
            this.emit('error', 'Language unavailable');
        }
        this._makeSound(jodit_plugins_speech_recognize_constants__WEBPACK_IMPORTED_MODULE_5__.WARN);
        this.emit('pulse', false);
        this.stop();
    }
    _makeSound(frequency) {
        if (this.sound) {
            (0,_sound__WEBPACK_IMPORTED_MODULE_4__.sound)({
                frequency
            });
        }
    }
    constructor(async, api){
        super(), (0,_swc_helpers_define_property__WEBPACK_IMPORTED_MODULE_0__._)(this, "async", void 0), (0,_swc_helpers_define_property__WEBPACK_IMPORTED_MODULE_0__._)(this, "_lang", void 0), (0,_swc_helpers_define_property__WEBPACK_IMPORTED_MODULE_0__._)(this, "_continuous", void 0), (0,_swc_helpers_define_property__WEBPACK_IMPORTED_MODULE_0__._)(this, "_interimResults", void 0), (0,_swc_helpers_define_property__WEBPACK_IMPORTED_MODULE_0__._)(this, "sound", void 0), (0,_swc_helpers_define_property__WEBPACK_IMPORTED_MODULE_0__._)(this, "_isEnabled", void 0), (0,_swc_helpers_define_property__WEBPACK_IMPORTED_MODULE_0__._)(this, "_restartTimeout", void 0), (0,_swc_helpers_define_property__WEBPACK_IMPORTED_MODULE_0__._)(this, "_onSpeechStart", void 0), (0,_swc_helpers_define_property__WEBPACK_IMPORTED_MODULE_0__._)(this, "_api", void 0), (0,_swc_helpers_define_property__WEBPACK_IMPORTED_MODULE_0__._)(this, "__interimResults", void 0), this.async = async, this._continuous = false, this._interimResults = false, this.sound = true, this._isEnabled = false, this._restartTimeout = 0, this._onSpeechStart = (e)=>{
            if (!this._isEnabled) {
                return;
            }
            this.async.clearTimeout(this._restartTimeout);
            this._restartTimeout = this.async.setTimeout(()=>{
                this.restart();
                this.emit('pulse', false);
                this._makeSound(jodit_plugins_speech_recognize_constants__WEBPACK_IMPORTED_MODULE_5__.WARN);
            }, 5000);
            this.emit('pulse', true);
        }, this.__interimResults = '';
        this._api = api;
        RecognizeManager._instances.add(this);
    }
}
(0,_swc_helpers_define_property__WEBPACK_IMPORTED_MODULE_0__._)(RecognizeManager, "_instances", new Set());
(0,_swc_helpers_ts_decorate__WEBPACK_IMPORTED_MODULE_1__.__decorate)([
    jodit_core_decorators__WEBPACK_IMPORTED_MODULE_2__.autobind
], RecognizeManager.prototype, "_onResults", null);
(0,_swc_helpers_ts_decorate__WEBPACK_IMPORTED_MODULE_1__.__decorate)([
    jodit_core_decorators__WEBPACK_IMPORTED_MODULE_2__.autobind
], RecognizeManager.prototype, "_onProgress", null);
(0,_swc_helpers_ts_decorate__WEBPACK_IMPORTED_MODULE_1__.__decorate)([
    jodit_core_decorators__WEBPACK_IMPORTED_MODULE_2__.autobind
], RecognizeManager.prototype, "_onError", null);


/***/ }),

/***/ 75143:
/***/ (function(__unused_webpack_module, __unused_webpack___webpack_exports__, __webpack_require__) {

"use strict";
/* harmony import */ var jodit_core_helpers_checker_is_boolean__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(22289);
/* harmony import */ var jodit_core_helpers_checker_is_string__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(85932);
/* harmony import */ var jodit_core_helpers_utils_attr__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(7909);
/* harmony import */ var jodit_core_helpers_utils_data_bind__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(36400);
/* harmony import */ var jodit_core_ui_icon__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(29434);
/* harmony import */ var jodit_config__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(5266);
/* harmony import */ var _helpers_api__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(97743);
/* harmony import */ var _helpers_recognize_manager__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(68097);
/* harmony import */ var _speech_recognize_svg__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(22227);
/* harmony import */ var _speech_recognize_svg__WEBPACK_IMPORTED_MODULE_8___default = /*#__PURE__*/__webpack_require__.n(_speech_recognize_svg__WEBPACK_IMPORTED_MODULE_8__);
/*!
 * Jodit Editor (https://xdsoft.net/jodit/)
 * Released under MIT see LICENSE.txt in the project root for license information.
 * Copyright (c) 2013-2025 Valeriy Chupurnov. All rights reserved. https://xdsoft.net
 */ /**
 * @module plugins/speech-recognize
 */ 








jodit_config__WEBPACK_IMPORTED_MODULE_5__.Config.prototype.speechRecognize = {
    api: typeof _helpers_api__WEBPACK_IMPORTED_MODULE_6__.SpeechRecognition !== 'undefined' ? _helpers_api__WEBPACK_IMPORTED_MODULE_6__.SpeechRecognition : null,
    sound: true,
    continuous: false,
    interimResults: true,
    commands: {
        'newline|enter': 'enter',
        'delete|remove word|delete word': 'backspaceWordButton',
        comma: 'inserthtml::,',
        underline: 'inserthtml::_',
        hyphen: 'inserthtml::-',
        space: 'inserthtml:: ',
        question: 'inserthtml::?',
        dot: 'inserthtml::.',
        'quote|quotes|open quote': "inserthtml::'",
        'header|header h1': 'formatblock::h1',
        'select all': 'selectall'
    }
};
jodit_core_ui_icon__WEBPACK_IMPORTED_MODULE_4__.Icon.set('speech-recognize', (_speech_recognize_svg__WEBPACK_IMPORTED_MODULE_8___default()));
jodit_config__WEBPACK_IMPORTED_MODULE_5__.Config.prototype.controls.speechRecognize = {
    isVisible (j) {
        return Boolean(j.o.speechRecognize.api);
    },
    isActive (jodit, _) {
        const api = (0,jodit_core_helpers_utils_data_bind__WEBPACK_IMPORTED_MODULE_3__.dataBind)(jodit, 'speech');
        return Boolean(api?.isEnabled);
    },
    isDisabled (jodit) {
        return !jodit.o.speechRecognize.api;
    },
    exec (jodit, current, { button, control }) {
        const { api: ApiConstructor, lang, continuous, interimResults, sound } = jodit.o.speechRecognize;
        if (!ApiConstructor) {
            jodit.alert('Speech recognize API unsupported in your browser');
            return;
        }
        let api = (0,jodit_core_helpers_utils_data_bind__WEBPACK_IMPORTED_MODULE_3__.dataBind)(jodit, 'speech');
        if (!api) {
            const nativeApi = new ApiConstructor();
            api = new _helpers_recognize_manager__WEBPACK_IMPORTED_MODULE_7__.RecognizeManager(jodit.async, nativeApi);
            api.lang = (0,jodit_core_helpers_checker_is_string__WEBPACK_IMPORTED_MODULE_1__.isString)(lang) ? lang : (0,jodit_core_helpers_utils_attr__WEBPACK_IMPORTED_MODULE_2__.attr)(jodit.od.documentElement, 'lang') ?? undefined;
            api.continuous = continuous;
            api.interimResults = interimResults;
            api.sound = sound;
            (0,jodit_core_helpers_utils_data_bind__WEBPACK_IMPORTED_MODULE_3__.dataBind)(jodit, 'speech', api);
            api.on('pulse', (enable)=>{
                button.setMod('pulse', enable);
            });
            api.on('result', (text)=>jodit.e.fire('speechRecognizeResult', text));
            api.on('progress', (text)=>jodit.e.fire('speechRecognizeProgressResult', text));
            api.on('error', (text)=>jodit.message.error(text));
            button.hookStatus('beforeDestruct', ()=>{
                (0,jodit_core_helpers_utils_data_bind__WEBPACK_IMPORTED_MODULE_3__.dataBind)(jodit, 'speech', null);
                api.destruct();
            });
        }
        if (control.args) {
            const key = control.args[0];
            if ((0,jodit_core_helpers_checker_is_boolean__WEBPACK_IMPORTED_MODULE_0__.isBoolean)(api[key])) {
                api[key] = !api[key];
                if (api.isEnabled) {
                    api.restart();
                }
                return;
            }
        }
        api.toggle();
        if (api.isEnabled) {
            button.setMod('pulse', true);
        }
        button.state.activated = api.isEnabled;
    },
    name: 'speechRecognize',
    command: 'toggleSpeechRecognize',
    tooltip: 'Speech Recognize',
    list: {
        sound: 'Sound',
        interimResults: 'Interim Results'
    },
    childTemplate (jodit, key, value) {
        const api = (0,jodit_core_helpers_utils_data_bind__WEBPACK_IMPORTED_MODULE_3__.dataBind)(jodit, 'speech'), checked = api?.[key] ?? jodit.o.speechRecognize[key];
        return `<span class='jodit-speech-recognize__list-item'><input ${checked ? 'checked' : ''} class='jodit-checkbox' type='checkbox'>&nbsp;${value}</span>`;
    },
    mods: {
        stroke: false
    }
};


/***/ }),

/***/ 86581:
/***/ (function(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

"use strict";
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   execSpellCommand: function() { return /* binding */ execSpellCommand; }
/* harmony export */ });
/*!
 * Jodit Editor (https://xdsoft.net/jodit/)
 * Released under MIT see LICENSE.txt in the project root for license information.
 * Copyright (c) 2013-2025 Valeriy Chupurnov. All rights reserved. https://xdsoft.net
 */ /**
 * @module plugins/speech-recognize
 */ function execSpellCommand(jodit, commandSentence) {
    const [command, value] = commandSentence.split('::');
    jodit.execCommand(command, null, value);
}


/***/ }),

/***/ 94092:
/***/ (function(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

"use strict";
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   PII: function() { return /* binding */ PII; },
/* harmony export */   WARN: function() { return /* binding */ WARN; }
/* harmony export */ });
/*!
 * Jodit Editor (https://xdsoft.net/jodit/)
 * Released under MIT see LICENSE.txt in the project root for license information.
 * Copyright (c) 2013-2025 Valeriy Chupurnov. All rights reserved. https://xdsoft.net
 */ /**
 * @module plugins/speech-recognize
 * @internal
 */ const PII = 440;
const WARN = 940;


/***/ }),

/***/ 97743:
/***/ (function(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

"use strict";
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   SpeechRecognition: function() { return /* binding */ SpeechRecognition; }
/* harmony export */ });
/* harmony import */ var jodit_core_constants__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(81937);
/*!
 * Jodit Editor (https://xdsoft.net/jodit/)
 * Released under MIT see LICENSE.txt in the project root for license information.
 * Copyright (c) 2013-2025 Valeriy Chupurnov. All rights reserved. https://xdsoft.net
 */ /**
 * @module plugins/speech-recognize
 */ 
const SpeechRecognition = jodit_core_constants__WEBPACK_IMPORTED_MODULE_0__.globalWindow ? jodit_core_constants__WEBPACK_IMPORTED_MODULE_0__.globalWindow.SpeechRecognition || jodit_core_constants__WEBPACK_IMPORTED_MODULE_0__.globalWindow.webkitSpeechRecognition : undefined;


/***/ })

},
/******/ function(__webpack_require__) { // webpackRuntimeModules
/******/ var __webpack_exec__ = function(moduleId) { return __webpack_require__(__webpack_require__.s = moduleId); }
/******/ var __webpack_exports__ = (__webpack_exec__(31262));
/******/ return __webpack_exports__;
/******/ }
]);
});