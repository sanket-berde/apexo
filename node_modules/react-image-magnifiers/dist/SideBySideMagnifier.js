"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports["default"] = void 0;

var _react = _interopRequireDefault(require("react"));

var _propTypes = _interopRequireDefault(require("prop-types"));

var _utils = _interopRequireDefault(require("./utils"));

var _reactInputPosition = _interopRequireWildcard(require("react-input-position"));

var _SideBySideRenderer = _interopRequireDefault(require("./SideBySideRenderer"));

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) { var desc = Object.defineProperty && Object.getOwnPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : {}; if (desc.get || desc.set) { Object.defineProperty(newObj, key, desc); } else { newObj[key] = obj[key]; } } } } newObj["default"] = obj; return newObj; } }

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { "default": obj }; }

var SideBySideMagnifier = function SideBySideMagnifier(props) {
  var imageSrc = props.imageSrc,
      largeImageSrc = props.largeImageSrc,
      imageAlt = props.imageAlt,
      overlayOpacity = props.overlayOpacity,
      overlayBoxOpacity = props.overlayBoxOpacity,
      cursorStyle = props.cursorStyle,
      alwaysInPlace = props.alwaysInPlace,
      transitionSpeed = props.transitionSpeed,
      transitionSpeedInPlace = props.transitionSpeedInPlace,
      renderOverlay = props.renderOverlay,
      className = props.className,
      style = props.style,
      onImageLoad = props.onImageLoad,
      onLargeImageLoad = props.onLargeImageLoad;
  return _react["default"].createElement(_reactInputPosition["default"], {
    style: style,
    className: className,
    touchActivationMethod: _reactInputPosition.TOUCH_ACTIVATION.TOUCH,
    mouseActivationMethod: _reactInputPosition.MOUSE_ACTIVATION.HOVER,
    trackItemPosition: true,
    linkItemToActive: true
  }, _react["default"].createElement(_SideBySideRenderer["default"], {
    imageSrc: imageSrc,
    largeImageSrc: largeImageSrc,
    imageAlt: imageAlt,
    overlayOpacity: overlayOpacity,
    overlayBoxOpacity: overlayBoxOpacity,
    alwaysInPlace: alwaysInPlace,
    transitionSpeed: transitionSpeed,
    transitionSpeedInPlace: transitionSpeedInPlace,
    renderOverlay: renderOverlay,
    cursorStyle: cursorStyle,
    onImageLoad: onImageLoad,
    onLargeImageLoad: onLargeImageLoad
  }));
};

SideBySideMagnifier.propTypes = {
  imageSrc: _propTypes["default"].oneOfType([_propTypes["default"].string, _propTypes["default"].arrayOf(_propTypes["default"].string)]),
  largeImageSrc: _propTypes["default"].oneOfType([_propTypes["default"].string, _propTypes["default"].arrayOf(_propTypes["default"].string)]),
  imageAlt: _propTypes["default"].string,
  overlayOpacity: _propTypes["default"].number,
  overlayBoxOpacity: _propTypes["default"].number,
  cursorStyle: _propTypes["default"].string,
  alwaysInPlace: _propTypes["default"].bool,
  transitionSpeed: _propTypes["default"].number,
  transitionSpeedInPlace: _propTypes["default"].number,
  renderOverlay: _propTypes["default"].func,
  className: _propTypes["default"].string,
  style: _propTypes["default"].object,
  onImageLoad: _propTypes["default"].func,
  onLargeImageLoad: _propTypes["default"].func
};
SideBySideMagnifier.defaultProps = {
  imageSrc: "",
  largeImageSrc: "",
  imageAlt: "",
  overlayOpacity: 0.5,
  overlayBoxOpacity: 0.8,
  cursorStyle: "crosshair",
  transitionSpeed: 0.4,
  transitionSpeedInPlace: 0.4,
  onImageLoad: _utils["default"].noop,
  onLargeImageLoad: _utils["default"].noop
};
var _default = SideBySideMagnifier;
exports["default"] = _default;