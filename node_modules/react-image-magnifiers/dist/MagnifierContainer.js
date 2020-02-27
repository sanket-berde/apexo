"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports["default"] = exports.MagnifierContext = void 0;

var _react = _interopRequireWildcard(require("react"));

var _propTypes = _interopRequireDefault(require("prop-types"));

var _reactInputPosition = require("react-input-position");

var _utils = _interopRequireDefault(require("./utils"));

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

var MagnifierContext = _react["default"].createContext();

exports.MagnifierContext = MagnifierContext;

var MagnifierContainer =
/*#__PURE__*/
function (_Component) {
  _inherits(MagnifierContainer, _Component);

  function MagnifierContainer() {
    var _getPrototypeOf2;

    var _this;

    _classCallCheck(this, MagnifierContainer);

    for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
      args[_key] = arguments[_key];
    }

    _this = _possibleConstructorReturn(this, (_getPrototypeOf2 = _getPrototypeOf(MagnifierContainer)).call.apply(_getPrototypeOf2, [this].concat(args)));

    _defineProperty(_assertThisInitialized(_this), "state", {
      inputPositionState: _reactInputPosition.defaultState,
      zoomImageDimensions: {},
      zoomContainerDimensions: {}
    });

    _defineProperty(_assertThisInitialized(_this), "zoomContainerRef", _react["default"].createRef());

    _defineProperty(_assertThisInitialized(_this), "getZoomContainerDimensions", function () {
      if (!_this.zoomContainerRef.current) {
        return {
          width: 0,
          height: 0
        };
      }

      var _this$zoomContainerRe = _this.zoomContainerRef.current.getBoundingClientRect(),
          width = _this$zoomContainerRe.width,
          height = _this$zoomContainerRe.height;

      return {
        width: width,
        height: height
      };
    });

    _defineProperty(_assertThisInitialized(_this), "onUpdate", function (changes) {
      _this.setState({
        inputPositionState: changes
      });
    });

    _defineProperty(_assertThisInitialized(_this), "onZoomImageLoad", function (e) {
      var rect = e.target.getBoundingClientRect();

      _this.setState({
        zoomImageDimensions: {
          width: rect.width,
          height: rect.height
        }
      });
    });

    return _this;
  }

  _createClass(MagnifierContainer, [{
    key: "getContextValue",
    value: function getContextValue() {
      return _objectSpread({
        stateOverride: this.state.inputPositionState,
        isActive: this.state.inputPositionState.active,
        onUpdate: this.onUpdate,
        zoomImageDimensions: this.state.zoomImageDimensions,
        zoomRef: this.zoomContainerRef,
        onZoomImageLoad: this.onZoomImageLoad
      }, this.calculatePositions());
    }
  }, {
    key: "calculatePositions",
    value: function calculatePositions() {
      var _this$state$inputPosi = this.state.inputPositionState,
          elementDimensions = _this$state$inputPosi.elementDimensions,
          itemPosition = _this$state$inputPosi.itemPosition;
      var zoomImageDimensions = this.state.zoomImageDimensions;
      var zoomContainerDimensions = this.getZoomContainerDimensions();
      var smallImageSize = {
        width: elementDimensions.width,
        height: elementDimensions.height
      };
      var previewSize = {
        width: Math.floor(smallImageSize.width * (zoomContainerDimensions.width / zoomImageDimensions.width)),
        height: Math.floor(smallImageSize.height * (zoomContainerDimensions.height / zoomImageDimensions.height))
      };
      var position = {
        x: 0,
        y: 0
      };

      var itemPositionAdj = _objectSpread({}, itemPosition);

      var previewOffset = {
        x: previewSize.width / 2,
        y: previewSize.height / 2
      };
      itemPositionAdj.x = Math.max(previewOffset.x, itemPositionAdj.x);
      itemPositionAdj.x = Math.min(smallImageSize.width - previewOffset.x, itemPositionAdj.x);
      itemPositionAdj.y = Math.max(previewOffset.y, itemPositionAdj.y);
      itemPositionAdj.y = Math.min(smallImageSize.height - previewOffset.y, itemPositionAdj.y);
      position = _objectSpread({}, itemPositionAdj);
      position.x = _utils["default"].convertRange(previewOffset.x, smallImageSize.width - previewOffset.x, zoomImageDimensions.width * -1 + zoomContainerDimensions.width, 0, position.x);
      position.y = _utils["default"].convertRange(previewOffset.y, smallImageSize.height - previewOffset.y, zoomImageDimensions.height * -1 + zoomContainerDimensions.height, 0, position.y);
      position.x = _utils["default"].invertNumber(zoomImageDimensions.width * -1 + zoomContainerDimensions.width, 0, position.x);
      position.y = _utils["default"].invertNumber(zoomImageDimensions.height * -1 + zoomContainerDimensions.height, 0, position.y);
      previewSize.left = Math.floor(itemPositionAdj.x - previewOffset.x) || 0;
      previewSize.right = Math.floor(itemPositionAdj.x + previewOffset.x) || 0;
      previewSize.top = Math.floor(itemPositionAdj.y - previewOffset.y) || 0;
      previewSize.bottom = Math.floor(itemPositionAdj.y + previewOffset.y) || 0;
      return {
        position: position,
        smallImageSize: smallImageSize,
        previewSize: previewSize,
        zoomContainerDimensions: zoomContainerDimensions
      };
    }
  }, {
    key: "render",
    value: function render() {
      var _this$props = this.props,
          style = _this$props.style,
          className = _this$props.className;
      return _react["default"].createElement("div", {
        style: style,
        className: className
      }, _react["default"].createElement(MagnifierContext.Provider, {
        value: this.getContextValue()
      }, this.props.children));
    }
  }]);

  return MagnifierContainer;
}(_react.Component);

_defineProperty(MagnifierContainer, "propTypes", {
  className: _propTypes["default"].string,
  style: _propTypes["default"].object
});

var _default = MagnifierContainer;
exports["default"] = _default;