"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports["default"] = void 0;

var _react = _interopRequireWildcard(require("react"));

var _propTypes = _interopRequireDefault(require("prop-types"));

var _utils = _interopRequireDefault(require("./utils"));

var _reactInputPosition = _interopRequireWildcard(require("react-input-position"));

var _PictureInPictureRenderer = _interopRequireDefault(require("./PictureInPictureRenderer"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { "default": obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) { var desc = Object.defineProperty && Object.getOwnPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : {}; if (desc.get || desc.set) { Object.defineProperty(newObj, key, desc); } else { newObj[key] = obj[key]; } } } } newObj["default"] = obj; return newObj; } }

function _typeof(obj) { if (typeof Symbol === "function" && typeof Symbol.iterator === "symbol") { _typeof = function _typeof(obj) { return typeof obj; }; } else { _typeof = function _typeof(obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; }; } return _typeof(obj); }

function ownKeys(object, enumerableOnly) { var keys = Object.keys(object); if (Object.getOwnPropertySymbols) { var symbols = Object.getOwnPropertySymbols(object); if (enumerableOnly) symbols = symbols.filter(function (sym) { return Object.getOwnPropertyDescriptor(object, sym).enumerable; }); keys.push.apply(keys, symbols); } return keys; }

function _objectSpread(target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i] != null ? arguments[i] : {}; if (i % 2) { ownKeys(source, true).forEach(function (key) { _defineProperty(target, key, source[key]); }); } else if (Object.getOwnPropertyDescriptors) { Object.defineProperties(target, Object.getOwnPropertyDescriptors(source)); } else { ownKeys(source).forEach(function (key) { Object.defineProperty(target, key, Object.getOwnPropertyDescriptor(source, key)); }); } } return target; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } }

function _createClass(Constructor, protoProps, staticProps) { if (protoProps) _defineProperties(Constructor.prototype, protoProps); if (staticProps) _defineProperties(Constructor, staticProps); return Constructor; }

function _possibleConstructorReturn(self, call) { if (call && (_typeof(call) === "object" || typeof call === "function")) { return call; } return _assertThisInitialized(self); }

function _getPrototypeOf(o) { _getPrototypeOf = Object.setPrototypeOf ? Object.getPrototypeOf : function _getPrototypeOf(o) { return o.__proto__ || Object.getPrototypeOf(o); }; return _getPrototypeOf(o); }

function _assertThisInitialized(self) { if (self === void 0) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function"); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, writable: true, configurable: true } }); if (superClass) _setPrototypeOf(subClass, superClass); }

function _setPrototypeOf(o, p) { _setPrototypeOf = Object.setPrototypeOf || function _setPrototypeOf(o, p) { o.__proto__ = p; return o; }; return _setPrototypeOf(o, p); }

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

var PictureInPictureMagnifier =
/*#__PURE__*/
function (_Component) {
  _inherits(PictureInPictureMagnifier, _Component);

  function PictureInPictureMagnifier() {
    var _getPrototypeOf2;

    var _this;

    _classCallCheck(this, PictureInPictureMagnifier);

    for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
      args[_key] = arguments[_key];
    }

    _this = _possibleConstructorReturn(this, (_getPrototypeOf2 = _getPrototypeOf(PictureInPictureMagnifier)).call.apply(_getPrototypeOf2, [this].concat(args)));

    _defineProperty(_assertThisInitialized(_this), "containerRef", _react["default"].createRef());

    return _this;
  }

  _createClass(PictureInPictureMagnifier, [{
    key: "render",
    value: function render() {
      var _this$props = this.props,
          imageSrc = _this$props.imageSrc,
          largeImageSrc = _this$props.largeImageSrc,
          imageAlt = _this$props.imageAlt,
          previewSizePercentage = _this$props.previewSizePercentage,
          previewHorizontalPos = _this$props.previewHorizontalPos,
          previewVerticalPos = _this$props.previewVerticalPos,
          previewOpacity = _this$props.previewOpacity,
          previewOverlayOpacity = _this$props.previewOverlayOpacity,
          previewOverlayBoxOpacity = _this$props.previewOverlayBoxOpacity,
          cursorStyle = _this$props.cursorStyle,
          cursorStyleActive = _this$props.cursorStyleActive,
          shadow = _this$props.shadow,
          shadowColor = _this$props.shadowColor,
          renderOverlay = _this$props.renderOverlay,
          className = _this$props.className,
          style = _this$props.style,
          onImageLoad = _this$props.onImageLoad,
          onLargeImageLoad = _this$props.onLargeImageLoad;
      return _react["default"].createElement("div", {
        ref: this.containerRef,
        style: _objectSpread({}, style, {
          textAlign: previewHorizontalPos,
          overflow: "hidden",
          fontSize: "0"
        }),
        className: className
      }, _react["default"].createElement(_reactInputPosition["default"], {
        style: {
          width: "".concat(previewSizePercentage, "%"),
          display: "inline-block",
          boxShadow: shadow ? "1px -1px 1px ".concat(shadowColor) : "none"
        },
        touchActivationMethod: _reactInputPosition.TOUCH_ACTIVATION.TOUCH,
        mouseActivationMethod: _reactInputPosition.MOUSE_ACTIVATION.MOUSE_DOWN,
        trackItemPosition: true,
        itemPositionMinX: 0,
        itemPositionMinY: 0,
        itemPositionMaxX: -0.1,
        itemPositionMaxY: -0.1,
        linkItemToActive: true,
        centerItemOnLoad: true
      }, _react["default"].createElement(_PictureInPictureRenderer["default"], {
        containerRef: this.containerRef,
        previewSizePercentage: previewSizePercentage,
        previewVerticalPos: previewVerticalPos,
        previewOpacity: previewOpacity,
        previewOverlayOpacity: previewOverlayOpacity,
        previewOverlayBoxOpacity: previewOverlayBoxOpacity,
        imageSrc: imageSrc,
        largeImageSrc: largeImageSrc,
        imageAlt: imageAlt,
        renderOverlay: renderOverlay,
        cursorStyle: cursorStyle,
        cursorStyleActive: cursorStyleActive || cursorStyle,
        onImageLoad: onImageLoad,
        onLargeImageLoad: onLargeImageLoad
      })));
    }
  }]);

  return PictureInPictureMagnifier;
}(_react.Component);

_defineProperty(PictureInPictureMagnifier, "propTypes", {
  imageSrc: _propTypes["default"].oneOfType([_propTypes["default"].string, _propTypes["default"].arrayOf(_propTypes["default"].string)]),
  largeImageSrc: _propTypes["default"].oneOfType([_propTypes["default"].string, _propTypes["default"].arrayOf(_propTypes["default"].string)]),
  imageAlt: _propTypes["default"].string,
  previewSizePercentage: _propTypes["default"].number,
  previewHorizontalPos: _propTypes["default"].oneOf(["left", "right"]),
  previewVerticalPos: _propTypes["default"].oneOf(["top", "bottom"]),
  previewOpacity: _propTypes["default"].number,
  previewOverlayOpacity: _propTypes["default"].number,
  previewOverlayBoxOpacity: _propTypes["default"].number,
  cursorStyle: _propTypes["default"].string,
  cursorStyleActive: _propTypes["default"].string,
  shadow: _propTypes["default"].bool,
  shadowColor: _propTypes["default"].string,
  renderOverlay: _propTypes["default"].func,
  className: _propTypes["default"].string,
  style: _propTypes["default"].object,
  onImageLoad: _propTypes["default"].func,
  onLargeImageLoad: _propTypes["default"].func
});

_defineProperty(PictureInPictureMagnifier, "defaultProps", {
  imageSrc: "",
  largeImageSrc: "",
  imageAlt: "",
  previewSizePercentage: 35,
  previewHorizontalPos: "left",
  previewVerticalPos: "bottom",
  previewOpacity: 0.8,
  previewOverlayOpacity: 0.4,
  previewOverlayBoxOpacity: 0.8,
  cursorStyle: "crosshair",
  cursorStyleActive: "",
  shadowColor: "rgba(0,0,0,.4)",
  onImageLoad: _utils["default"].noop,
  onLargeImageLoad: _utils["default"].noop
});

var _default = PictureInPictureMagnifier;
exports["default"] = _default;