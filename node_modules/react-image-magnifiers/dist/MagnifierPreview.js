"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports["default"] = void 0;

var _react = _interopRequireDefault(require("react"));

var _propTypes = _interopRequireDefault(require("prop-types"));

var _utils = _interopRequireDefault(require("./utils"));

var _reactInputPosition = _interopRequireWildcard(require("react-input-position"));

var _MagnifierPreviewRenderer = _interopRequireDefault(require("./MagnifierPreviewRenderer"));

var _MagnifierContainer = require("./MagnifierContainer");

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) { var desc = Object.defineProperty && Object.getOwnPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : {}; if (desc.get || desc.set) { Object.defineProperty(newObj, key, desc); } else { newObj[key] = obj[key]; } } } } newObj["default"] = obj; return newObj; } }

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { "default": obj }; }

function MagnifierPreview(props) {
  var imageSrc = props.imageSrc,
      imageAlt = props.imageAlt,
      className = props.className,
      style = props.style,
      cursorStyle = props.cursorStyle,
      onImageLoad = props.onImageLoad,
      renderOverlay = props.renderOverlay,
      overlayOpacity = props.overlayOpacity,
      overlayBoxOpacity = props.overlayBoxOpacity,
      transitionSpeed = props.transitionSpeed;

  var _React$useContext = _react["default"].useContext(_MagnifierContainer.MagnifierContext),
      stateOverride = _React$useContext.stateOverride,
      onUpdate = _React$useContext.onUpdate,
      zoomImageDimensions = _React$useContext.zoomImageDimensions,
      previewSize = _React$useContext.previewSize,
      smallImageSize = _React$useContext.smallImageSize;

  return _react["default"].createElement(_reactInputPosition["default"], {
    mouseActivationMethod: _reactInputPosition.MOUSE_ACTIVATION.HOVER,
    touchActivationMethod: _reactInputPosition.TOUCH_ACTIVATION.TOUCH,
    className: className,
    style: style,
    cursorStyle: cursorStyle,
    trackItemPosition: true,
    linkItemToActive: true,
    stateOverride: stateOverride,
    onUpdate: onUpdate
  }, _react["default"].createElement(_MagnifierPreviewRenderer["default"], {
    image: imageSrc,
    alt: imageAlt,
    zoomImageDimensions: zoomImageDimensions,
    previewSize: previewSize,
    smallImageSize: smallImageSize,
    onImageLoad: onImageLoad,
    renderOverlay: renderOverlay,
    overlayOpacity: overlayOpacity,
    overlayBoxOpacity: overlayBoxOpacity,
    transitionSpeed: transitionSpeed
  }));
}

MagnifierPreview.propTypes = {
  className: _propTypes["default"].string,
  style: _propTypes["default"].object,
  cursorStyle: _propTypes["default"].string,
  imageSrc: _propTypes["default"].oneOfType([_propTypes["default"].string, _propTypes["default"].arrayOf(_propTypes["default"].string)]),
  imageAlt: _propTypes["default"].string,
  onImageLoad: _propTypes["default"].func,
  renderOverlay: _propTypes["default"].func,
  overlayBoxOpacity: _propTypes["default"].number,
  overlayOpacity: _propTypes["default"].number,
  transitionSpeed: _propTypes["default"].number
};
MagnifierPreview.defaultProps = {
  cursorStyle: "crosshair",
  imageSrc: "",
  imageAlt: "",
  onImageLoad: _utils["default"].noop
};
var _default = MagnifierPreview;
exports["default"] = _default;