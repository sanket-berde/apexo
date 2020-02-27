"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports["default"] = void 0;

var _react = _interopRequireDefault(require("react"));

var _propTypes = _interopRequireDefault(require("prop-types"));

var _utils = _interopRequireDefault(require("./utils"));

var _reactInputPosition = _interopRequireWildcard(require("react-input-position"));

var _GlassRenderer = _interopRequireDefault(require("./GlassRenderer"));

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) { var desc = Object.defineProperty && Object.getOwnPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : {}; if (desc.get || desc.set) { Object.defineProperty(newObj, key, desc); } else { newObj[key] = obj[key]; } } } } newObj["default"] = obj; return newObj; } }

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { "default": obj }; }

function ownKeys(object, enumerableOnly) { var keys = Object.keys(object); if (Object.getOwnPropertySymbols) { var symbols = Object.getOwnPropertySymbols(object); if (enumerableOnly) symbols = symbols.filter(function (sym) { return Object.getOwnPropertyDescriptor(object, sym).enumerable; }); keys.push.apply(keys, symbols); } return keys; }

function _objectSpread(target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i] != null ? arguments[i] : {}; if (i % 2) { ownKeys(source, true).forEach(function (key) { _defineProperty(target, key, source[key]); }); } else if (Object.getOwnPropertyDescriptors) { Object.defineProperties(target, Object.getOwnPropertyDescriptors(source)); } else { ownKeys(source).forEach(function (key) { Object.defineProperty(target, key, Object.getOwnPropertyDescriptor(source, key)); }); } } return target; }

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

var GlassMagnifier = function GlassMagnifier(props) {
  var imageSrc = props.imageSrc,
      largeImageSrc = props.largeImageSrc,
      imageAlt = props.imageAlt,
      magnifierBorderSize = props.magnifierBorderSize,
      magnifierBorderColor = props.magnifierBorderColor,
      magnifierBackgroundColor = props.magnifierBackgroundColor,
      magnifierSize = props.magnifierSize,
      magnifierOffsetX = props.magnifierOffsetX,
      magnifierOffsetY = props.magnifierOffsetY,
      square = props.square,
      cursorStyle = props.cursorStyle,
      renderOverlay = props.renderOverlay,
      allowOverflow = props.allowOverflow,
      style = props.style,
      className = props.className,
      onImageLoad = props.onImageLoad,
      onLargeImageLoad = props.onLargeImageLoad;
  return _react["default"].createElement(_reactInputPosition["default"], {
    style: _objectSpread({}, style, {
      position: "relative",
      overflow: allowOverflow ? "visible" : "hidden"
    }),
    className: className,
    touchActivationMethod: _reactInputPosition.TOUCH_ACTIVATION.TOUCH,
    mouseActivationMethod: _reactInputPosition.MOUSE_ACTIVATION.HOVER,
    trackItemPosition: true,
    alignItemOnActivePos: true,
    itemPositionLimitBySize: true
  }, _react["default"].createElement(_GlassRenderer["default"], {
    magnifierBorderSize: magnifierBorderSize,
    magnifierBorderColor: magnifierBorderColor,
    magnifierBackgroundColor: magnifierBackgroundColor,
    magnifierSize: magnifierSize,
    imageSrc: imageSrc,
    largeImageSrc: largeImageSrc,
    imageAlt: imageAlt,
    square: square,
    magnifierOffsetX: magnifierOffsetX,
    magnifierOffsetY: magnifierOffsetY,
    renderOverlay: renderOverlay,
    cursorStyle: cursorStyle,
    onImageLoad: onImageLoad,
    onLargeImageLoad: onLargeImageLoad
  }));
};

GlassMagnifier.propTypes = {
  imageSrc: _propTypes["default"].oneOfType([_propTypes["default"].string, _propTypes["default"].arrayOf(_propTypes["default"].string)]),
  largeImageSrc: _propTypes["default"].oneOfType([_propTypes["default"].string, _propTypes["default"].arrayOf(_propTypes["default"].string)]),
  imageAlt: _propTypes["default"].string,
  allowOverflow: _propTypes["default"].bool,
  magnifierBorderSize: _propTypes["default"].number,
  magnifierBorderColor: _propTypes["default"].string,
  magnifierBackgroundColor: _propTypes["default"].string,
  magnifierSize: _propTypes["default"].oneOfType([_propTypes["default"].string, _propTypes["default"].number]),
  magnifierOffsetX: _propTypes["default"].number,
  magnifierOffsetY: _propTypes["default"].number,
  square: _propTypes["default"].bool,
  cursorStyle: _propTypes["default"].string,
  renderOverlay: _propTypes["default"].func,
  className: _propTypes["default"].string,
  style: _propTypes["default"].object,
  onImageLoad: _propTypes["default"].func,
  onLargeImageLoad: _propTypes["default"].func
};
GlassMagnifier.defaultProps = {
  imageSrc: "",
  largeImageSrc: "",
  imageAlt: "",
  allowOverflow: false,
  magnifierBorderSize: 3,
  magnifierBorderColor: "rgba(255,255,255,.5)",
  magnifierBackgroundColor: "rgba(225,225,225,.5)",
  magnifierSize: "25%",
  magnifierOffsetX: 0,
  magnifierOffsetY: 0,
  square: false,
  cursorStyle: "none",
  onImageLoad: _utils["default"].noop,
  onLargeImageLoad: _utils["default"].noop
};
var _default = GlassMagnifier;
exports["default"] = _default;