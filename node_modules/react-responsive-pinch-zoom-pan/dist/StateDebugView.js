"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

var _react = _interopRequireDefault(require("react"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

var style = {
  position: 'absolute',
  marginTop: '40px',
  marginLeft: '5px',
  backgroundColor: 'rgba(0,0,0,0)',
  zIndex: '1000',
  color: 'white'
};

var _default = function _default(_ref) {
  var top = _ref.top,
      left = _ref.left,
      scale = _ref.scale,
      overflow = _ref.overflow;
  var overflowDisplay = [overflow.top > 0 ? 'top' : '', overflow.right > 0 ? 'right' : '', overflow.bottom > 0 ? 'bottom' : '', overflow.left > 0 ? 'left' : ''].filter(function (o) {
    return o.length;
  }).join(', ') || 'none';
  return _react.default.createElement("div", {
    style: style
  }, _react.default.createElement("div", null, "top: ".concat(top)), _react.default.createElement("div", null, "left: ".concat(left)), _react.default.createElement("div", null, "scale: ".concat(scale)), _react.default.createElement("div", null, "overflow: ".concat(overflowDisplay)));
};

exports.default = _default;