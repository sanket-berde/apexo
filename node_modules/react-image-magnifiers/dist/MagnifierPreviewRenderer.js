"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports["default"] = void 0;

var _react = _interopRequireDefault(require("react"));

var _Image = _interopRequireDefault(require("./Image"));

var _ImagePreviewOverlay = _interopRequireDefault(require("./ImagePreviewOverlay"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { "default": obj }; }

function MagnifierPreviewRenderer(props) {
  var image = props.image,
      alt = props.alt,
      previewSize = props.previewSize,
      smallImageSize = props.smallImageSize,
      overlayOpacity = props.overlayOpacity,
      overlayBoxOpacity = props.overlayBoxOpacity,
      active = props.active,
      onImageLoad = props.onImageLoad,
      renderOverlay = props.renderOverlay,
      transitionSpeed = props.transitionSpeed;
  return _react["default"].createElement("div", {
    style: {
      position: "relative"
    }
  }, _react["default"].createElement(_Image["default"], {
    style: {
      display: "block",
      width: "100%"
    },
    src: image,
    alt: alt,
    onImageLoad: onImageLoad
  }), _react["default"].createElement(_ImagePreviewOverlay["default"], {
    previewWidth: previewSize.width,
    previewHeight: previewSize.height,
    previewPosLeft: previewSize.left,
    previewPosRight: previewSize.right,
    previewPosTop: previewSize.top,
    previewPosBottom: previewSize.bottom,
    imageWidth: smallImageSize.width,
    imageHeight: smallImageSize.height,
    overlayOpacity: overlayOpacity,
    overlayBoxOpacity: overlayBoxOpacity,
    active: active,
    transitionSpeed: transitionSpeed
  }), renderOverlay ? renderOverlay(active) : null);
}

var _default = MagnifierPreviewRenderer;
exports["default"] = _default;