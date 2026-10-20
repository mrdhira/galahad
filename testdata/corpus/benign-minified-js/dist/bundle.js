/******/ (function(modules) { // webpackBootstrap
/******/ 	var installedModules = {};
/******/ 	function __webpack_require__(moduleId) {
/******/ 		if(installedModules[moduleId]) {
/******/ 			return installedModules[moduleId].exports;
/******/ 		}
/******/ 		var module = installedModules[moduleId] = { i: moduleId, l: false, exports: {} };
/******/ 		modules[moduleId].call(module.exports, module, module.exports, __webpack_require__);
/******/ 		module.l = true;
/******/ 		return module.exports;
/******/ 	}
/******/ 	return __webpack_require__(__webpack_require__.s = "./src/index.js");
/******/ })
/************************************************************************/
/******/ ({

/***/ "./src/index.js":
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
eval("__webpack_require__.r(__webpack_exports__);\n/* harmony import */ var _util__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./util */ \"./src/util.js\");\n\nconst mode = \"development\" === 'production' ? 'prod' : 'dev';\nObject(_util__WEBPACK_IMPORTED_MODULE_0__[\"load\"])(mode);\n\n//# sourceURL=webpack:///./src/index.js?");

/***/ }),

/***/ "./src/util.js":
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
eval("__webpack_require__.r(__webpack_exports__);\n/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, \"load\", function() { return load; });\nfunction load(mode) {\n  const decoded = typeof atob === 'function' ? atob('aGVsbG8=') : '';\n  return fetch('/api/config?mode=' + mode).then((r) => r.json()).then((c) => console.log(decoded, c));\n}\n\n//# sourceURL=webpack:///./src/util.js?");

/***/ })

/******/ });
