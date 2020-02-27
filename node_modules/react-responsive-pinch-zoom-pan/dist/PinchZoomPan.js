"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

var _react = _interopRequireDefault(require("react"));

var _propTypes = _interopRequireDefault(require("prop-types"));

var _reselect = require("reselect");

var _warning = _interopRequireDefault(require("warning"));

var _ZoomButtons = _interopRequireDefault(require("./ZoomButtons"));

var _StateDebugView = _interopRequireDefault(require("./StateDebugView"));

var _Utils = require("./Utils");

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _typeof(obj) { if (typeof Symbol === "function" && typeof Symbol.iterator === "symbol") { _typeof = function _typeof(obj) { return typeof obj; }; } else { _typeof = function _typeof(obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; }; } return _typeof(obj); }

function _extends() { _extends = Object.assign || function (target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i]; for (var key in source) { if (Object.prototype.hasOwnProperty.call(source, key)) { target[key] = source[key]; } } } return target; }; return _extends.apply(this, arguments); }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } }

function _createClass(Constructor, protoProps, staticProps) { if (protoProps) _defineProperties(Constructor.prototype, protoProps); if (staticProps) _defineProperties(Constructor, staticProps); return Constructor; }

function _possibleConstructorReturn(self, call) { if (call && (_typeof(call) === "object" || typeof call === "function")) { return call; } return _assertThisInitialized(self); }

function _getPrototypeOf(o) { _getPrototypeOf = Object.setPrototypeOf ? Object.getPrototypeOf : function _getPrototypeOf(o) { return o.__proto__ || Object.getPrototypeOf(o); }; return _getPrototypeOf(o); }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function"); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, writable: true, configurable: true } }); if (superClass) _setPrototypeOf(subClass, superClass); }

function _setPrototypeOf(o, p) { _setPrototypeOf = Object.setPrototypeOf || function _setPrototypeOf(o, p) { o.__proto__ = p; return o; }; return _setPrototypeOf(o, p); }

function _assertThisInitialized(self) { if (self === void 0) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return self; }

function _objectSpread(target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i] != null ? arguments[i] : {}; var ownKeys = Object.keys(source); if (typeof Object.getOwnPropertySymbols === 'function') { ownKeys = ownKeys.concat(Object.getOwnPropertySymbols(source).filter(function (sym) { return Object.getOwnPropertyDescriptor(source, sym).enumerable; })); } ownKeys.forEach(function (key) { _defineProperty(target, key, source[key]); }); } return target; }

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

var OVERZOOM_TOLERANCE = 0.05;
var DOUBLE_TAP_THRESHOLD = 250;
var ANIMATION_SPEED = 0.1;

var isInitialized = function isInitialized(top, left, scale) {
  return scale !== undefined && left !== undefined && top !== undefined;
};

var imageStyle = (0, _reselect.createSelector)(function (state) {
  return state.top;
}, function (state) {
  return state.left;
}, function (state) {
  return state.scale;
}, function (top, left, scale) {
  var style = {
    cursor: 'pointer'
  };
  return isInitialized(top, left, scale) ? _objectSpread({}, style, {
    transform: "translate3d(".concat(left, "px, ").concat(top, "px, 0) scale(").concat(scale, ")"),
    transformOrigin: '0 0'
  }) : style;
});
var imageOverflow = (0, _reselect.createSelector)(function (state) {
  return state.top;
}, function (state) {
  return state.left;
}, function (state) {
  return state.scale;
}, function (state) {
  return state.imageDimensions;
}, function (state) {
  return state.containerDimensions;
}, function (top, left, scale, imageDimensions, containerDimensions) {
  if (!isInitialized(top, left, scale)) {
    return '';
  }

  return (0, _Utils.getImageOverflow)(top, left, scale, imageDimensions, containerDimensions);
});
var browserPanActions = (0, _reselect.createSelector)(imageOverflow, function (imageOverflow) {
  //Determine the panning directions where there is no image overflow and let
  //the browser handle those directions (e.g., scroll viewport if possible).
  //Need to replace 'pan-left pan-right' with 'pan-x', etc. otherwise 
  //it is rejected (o_O), therefore explicitly handle each combination.
  var browserPanX = !imageOverflow.left && !imageOverflow.right ? 'pan-x' //we can't pan the image horizontally, let the browser take it
  : !imageOverflow.left ? 'pan-left' : !imageOverflow.right ? 'pan-right' : '';
  var browserPanY = !imageOverflow.top && !imageOverflow.bottom ? 'pan-y' : !imageOverflow.top ? 'pan-up' : !imageOverflow.bottom ? 'pan-down' : '';
  return [browserPanX, browserPanY].join(' ').trim();
}); //Ensure the image is not over-panned, and not over- or under-scaled.
//These constraints must be checked when image changes, and when container is resized.

var PinchZoomPan =
/*#__PURE__*/
function (_React$Component) {
  _inherits(PinchZoomPan, _React$Component);

  function PinchZoomPan() {
    var _getPrototypeOf2;

    var _this;

    _classCallCheck(this, PinchZoomPan);

    for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
      args[_key] = arguments[_key];
    }

    _this = _possibleConstructorReturn(this, (_getPrototypeOf2 = _getPrototypeOf(PinchZoomPan)).call.apply(_getPrototypeOf2, [this].concat(args)));

    _defineProperty(_assertThisInitialized(_assertThisInitialized(_this)), "state", {});

    _defineProperty(_assertThisInitialized(_assertThisInitialized(_this)), "lastPointerUpTimeStamp", void 0);

    _defineProperty(_assertThisInitialized(_assertThisInitialized(_this)), "lastPanPointerPosition", void 0);

    _defineProperty(_assertThisInitialized(_assertThisInitialized(_this)), "lastPinchLength", void 0);

    _defineProperty(_assertThisInitialized(_assertThisInitialized(_this)), "animation", void 0);

    _defineProperty(_assertThisInitialized(_assertThisInitialized(_this)), "imageRef", void 0);

    _defineProperty(_assertThisInitialized(_assertThisInitialized(_this)), "isImageLoaded", void 0);

    _defineProperty(_assertThisInitialized(_assertThisInitialized(_this)), "originalOverscrollBehaviorY", void 0);

    _defineProperty(_assertThisInitialized(_assertThisInitialized(_this)), "handleTouchStart", function (event) {
      _this.cancelAnimation();

      var touches = event.touches;

      if (touches.length === 2) {
        _this.lastPinchLength = (0, _Utils.getPinchLength)(touches);
        _this.lastPanPointerPosition = null;
      } else if (touches.length === 1) {
        _this.lastPinchLength = null;

        _this.pointerDown(touches[0]);

        (0, _Utils.tryCancelEvent)(event); //suppress mouse events
      }
    });

    _defineProperty(_assertThisInitialized(_assertThisInitialized(_this)), "handleTouchMove", function (event) {
      var touches = event.touches;

      if (touches.length === 2) {
        _this.pinchChange(touches); //suppress viewport scaling on iOS


        (0, _Utils.tryCancelEvent)(event);
      } else if (touches.length === 1) {
        var requestedPan = _this.pan(touches[0]);

        if (!_this.controlOverscrollViaCss) {
          //let the browser handling panning if we are at the edge of the image in 
          //both pan directions, or if we are primarily panning in one direction
          //and are at the edge in that directino
          var overflow = imageOverflow(_this.state);
          var hasOverflowX = requestedPan.left && overflow.left > 0 || requestedPan.right && overflow.right > 0;
          var hasOverflowY = requestedPan.up && overflow.top > 0 || requestedPan.down && overflow.bottom > 0;

          if (!hasOverflowX && !hasOverflowY) {
            //no overflow in both directions
            return;
          }

          var panX = requestedPan.left || requestedPan.right;
          var panY = requestedPan.up || requestedPan.down;

          if (panY > 2 * panX && !hasOverflowY) {
            //primarily panning up or down and no overflow in the Y direction
            return;
          }

          if (panX > 2 * panY && !hasOverflowX) {
            //primarily panning left or right and no overflow in the X direction
            return;
          }

          (0, _Utils.tryCancelEvent)(event);
        }
      }
    });

    _defineProperty(_assertThisInitialized(_assertThisInitialized(_this)), "handleTouchEnd", function (event) {
      _this.cancelAnimation();

      if (event.touches.length === 0 && event.changedTouches.length === 1) {
        if (_this.lastPointerUpTimeStamp && _this.lastPointerUpTimeStamp + DOUBLE_TAP_THRESHOLD > event.timeStamp) {
          var pointerPosition = (0, _Utils.getRelativePosition)(event.changedTouches[0], _this.imageRef.parentNode);

          _this.doubleClick(pointerPosition);
        }

        _this.lastPointerUpTimeStamp = event.timeStamp;
        (0, _Utils.tryCancelEvent)(event); //suppress mouse events
      } //We allow transient +/-5% over-pinching.
      //Animate the bounce back to constraints if applicable.


      _this.maybeAdjustCurrentTransform(ANIMATION_SPEED);

      return;
    });

    _defineProperty(_assertThisInitialized(_assertThisInitialized(_this)), "handleMouseDown", function (event) {
      _this.cancelAnimation();

      _this.pointerDown(event);
    });

    _defineProperty(_assertThisInitialized(_assertThisInitialized(_this)), "handleMouseMove", function (event) {
      if (!event.buttons) return null;

      _this.pan(event);
    });

    _defineProperty(_assertThisInitialized(_assertThisInitialized(_this)), "handleMouseDoubleClick", function (event) {
      _this.cancelAnimation();

      var pointerPosition = (0, _Utils.getRelativePosition)(event, _this.imageRef.parentNode);

      _this.doubleClick(pointerPosition);
    });

    _defineProperty(_assertThisInitialized(_assertThisInitialized(_this)), "handleMouseWheel", function (event) {
      _this.cancelAnimation();

      var point = (0, _Utils.getRelativePosition)(event, _this.imageRef.parentNode);

      if (event.deltaY > 0) {
        if (_this.state.scale > (0, _Utils.getMinScale)(_this.state, _this.props)) {
          _this.zoomOut(point);

          (0, _Utils.tryCancelEvent)(event);
        }
      } else if (event.deltaY < 0) {
        if (_this.state.scale < _this.props.maxScale) {
          _this.zoomIn(point);

          (0, _Utils.tryCancelEvent)(event);
        }
      }
    });

    _defineProperty(_assertThisInitialized(_assertThisInitialized(_this)), "handleImageLoad", function (event) {
      _this.debug('handleImageLoad');

      _this.isImageLoaded = true;

      _this.maybeHandleDimensionsChanged();

      var _React$Children$only = _react.default.Children.only(_this.props.children),
          onLoad = _React$Children$only.onLoad;

      if (typeof onLoad === 'function') {
        onLoad(event);
      }
    });

    _defineProperty(_assertThisInitialized(_assertThisInitialized(_this)), "handleZoomInClick", function () {
      _this.cancelAnimation();

      _this.zoomIn();
    });

    _defineProperty(_assertThisInitialized(_assertThisInitialized(_this)), "handleZoomOutClick", function () {
      _this.cancelAnimation();

      _this.zoomOut();
    });

    _defineProperty(_assertThisInitialized(_assertThisInitialized(_this)), "handleWindowResize", function () {
      return _this.maybeHandleDimensionsChanged();
    });

    _defineProperty(_assertThisInitialized(_assertThisInitialized(_this)), "handleRefImage", function (ref) {
      if (_this.imageRef) {
        _this.cancelAnimation();

        _this.imageRef.removeEventListener('touchmove', _this.handleTouchMove);
      }

      _this.imageRef = ref;

      if (ref) {
        _this.imageRef.addEventListener('touchmove', _this.handleTouchMove, {
          passive: false
        });
      }

      var _React$Children$only2 = _react.default.Children.only(_this.props.children),
          imageRefProp = _React$Children$only2.ref;

      (0, _Utils.setRef)(imageRefProp, ref);
    });

    return _this;
  }

  _createClass(PinchZoomPan, [{
    key: "pointerDown",
    //actions
    value: function pointerDown(clientPosition) {
      this.lastPanPointerPosition = (0, _Utils.getRelativePosition)(clientPosition, this.imageRef.parentNode);
    }
  }, {
    key: "pan",
    value: function pan(pointerClientPosition) {
      if (!this.isTransformInitialized) {
        return;
      }

      if (!this.lastPanPointerPosition) {
        //if we were pinching and lifted a finger
        this.pointerDown(pointerClientPosition);
        return 0;
      }

      var pointerPosition = (0, _Utils.getRelativePosition)(pointerClientPosition, this.imageRef.parentNode);
      var translateX = pointerPosition.x - this.lastPanPointerPosition.x;
      var translateY = pointerPosition.y - this.lastPanPointerPosition.y;
      this.lastPanPointerPosition = pointerPosition;
      var top = this.state.top + translateY;
      var left = this.state.left + translateX;
      this.constrainAndApplyTransform(top, left, this.state.scale, 0, 0);
      return {
        up: translateY > 0 ? translateY : 0,
        down: translateY < 0 ? (0, _Utils.negate)(translateY) : 0,
        right: translateX < 0 ? (0, _Utils.negate)(translateX) : 0,
        left: translateX > 0 ? translateX : 0
      };
    }
  }, {
    key: "doubleClick",
    value: function doubleClick(pointerPosition) {
      if (String(this.props.doubleTapBehavior).toLowerCase() === 'zoom' && this.state.scale * (1 + OVERZOOM_TOLERANCE) < this.props.maxScale) {
        this.zoomIn(pointerPosition, ANIMATION_SPEED, 0.3);
      } else {
        //reset
        this.applyInitialTransform(ANIMATION_SPEED);
      }
    }
  }, {
    key: "pinchChange",
    value: function pinchChange(touches) {
      var length = (0, _Utils.getPinchLength)(touches);
      var midpoint = (0, _Utils.getPinchMidpoint)(touches);
      var scale = this.lastPinchLength ? this.state.scale * length / this.lastPinchLength //sometimes we get a touchchange before a touchstart when pinching
      : this.state.scale;
      this.zoom(scale, midpoint, OVERZOOM_TOLERANCE);
      this.lastPinchLength = length;
    }
  }, {
    key: "zoomIn",
    value: function zoomIn(midpoint) {
      var speed = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : 0;
      var factor = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : 0.1;
      midpoint = midpoint || {
        x: this.state.containerDimensions.width / 2,
        y: this.state.containerDimensions.height / 2
      };
      this.zoom(this.state.scale * (1 + factor), midpoint, 0, speed);
    }
  }, {
    key: "zoomOut",
    value: function zoomOut(midpoint) {
      midpoint = midpoint || {
        x: this.state.containerDimensions.width / 2,
        y: this.state.containerDimensions.height / 2
      };
      this.zoom(this.state.scale * 0.9, midpoint, 0);
    }
  }, {
    key: "zoom",
    value: function zoom(requestedScale, containerRelativePoint, tolerance) {
      var speed = arguments.length > 3 && arguments[3] !== undefined ? arguments[3] : 0;

      if (!this.isTransformInitialized) {
        return;
      }

      var _this$state = this.state,
          scale = _this$state.scale,
          top = _this$state.top,
          left = _this$state.left;
      var imageRelativePoint = {
        top: containerRelativePoint.y - top,
        left: containerRelativePoint.x - left
      };
      var nextScale = this.getConstrainedScale(requestedScale, tolerance);
      var incrementalScalePercentage = (nextScale - scale) / scale;
      var translateY = imageRelativePoint.top * incrementalScalePercentage;
      var translateX = imageRelativePoint.left * incrementalScalePercentage;
      var nextTop = top - translateY;
      var nextLeft = left - translateX;
      this.constrainAndApplyTransform(nextTop, nextLeft, nextScale, tolerance, speed);
    } //compare stored dimensions to actual dimensions; capture actual dimensions if different

  }, {
    key: "maybeHandleDimensionsChanged",
    value: function maybeHandleDimensionsChanged() {
      var _this2 = this;

      if (this.isImageReady) {
        var containerDimensions = (0, _Utils.getContainerDimensions)(this.imageRef);
        var imageDimensions = (0, _Utils.getDimensions)(this.imageRef);

        if (!(0, _Utils.isEqualDimensions)(containerDimensions, (0, _Utils.getDimensions)(this.state.containerDimensions)) || !(0, _Utils.isEqualDimensions)(imageDimensions, (0, _Utils.getDimensions)(this.state.imageDimensions))) {
          this.cancelAnimation(); //capture new dimensions

          this.setState({
            containerDimensions: containerDimensions,
            imageDimensions: imageDimensions
          }, function () {
            //When image loads and image dimensions are first established, apply initial transform.
            //If dimensions change, constraints change; current transform may need to be adjusted.
            //Transforms depend on state, so wait until state is updated.
            if (!_this2.isTransformInitialized) {
              _this2.applyInitialTransform();
            } else {
              _this2.maybeAdjustCurrentTransform();
            }
          });
          this.debug("Dimensions changed: Container: ".concat(containerDimensions.width, ", ").concat(containerDimensions.height, ", Image: ").concat(imageDimensions.width, ", ").concat(imageDimensions.height));
        }
      } else {
        this.debug('Image not loaded');
      }
    } //transformation methods
    //Zooming and panning cause transform to be requested.

  }, {
    key: "constrainAndApplyTransform",
    value: function constrainAndApplyTransform(requestedTop, requestedLeft, requestedScale, tolerance) {
      var speed = arguments.length > 4 && arguments[4] !== undefined ? arguments[4] : 0;
      var requestedTransform = {
        top: requestedTop,
        left: requestedLeft,
        scale: requestedScale
      };
      this.debug("Requesting transform: left ".concat(requestedLeft, ", top ").concat(requestedTop, ", scale ").concat(requestedScale)); //Correct the transform if needed to prevent overpanning and overzooming

      var transform = this.getCorrectedTransform(requestedTransform, tolerance) || requestedTransform;
      this.debug("Applying transform: left ".concat(transform.left, ", top ").concat(transform.top, ", scale ").concat(transform.scale));

      if ((0, _Utils.isEqualTransform)(transform, this.state)) {
        return false;
      }

      this.applyTransform(transform, speed);
      return true;
    }
  }, {
    key: "applyTransform",
    value: function applyTransform(_ref, speed) {
      var _this3 = this;

      var top = _ref.top,
          left = _ref.left,
          scale = _ref.scale;

      if (speed > 0) {
        var frame = function frame() {
          var translateY = top - _this3.state.top;
          var translateX = left - _this3.state.left;
          var translateScale = scale - _this3.state.scale;
          var nextTransform = {
            top: (0, _Utils.snapToTarget)(_this3.state.top + speed * translateY, top, 1),
            left: (0, _Utils.snapToTarget)(_this3.state.left + speed * translateX, left, 1),
            scale: (0, _Utils.snapToTarget)(_this3.state.scale + speed * translateScale, scale, 0.001)
          }; //animation runs until we reach the target

          if (!(0, _Utils.isEqualTransform)(nextTransform, _this3.state)) {
            _this3.setState(nextTransform, function () {
              return _this3.animation = requestAnimationFrame(frame);
            });
          }
        };

        this.animation = requestAnimationFrame(frame);
      } else {
        this.setState({
          top: top,
          left: left,
          scale: scale
        });
      }
    } //Returns constrained scale when requested scale is outside min/max with tolerance, otherwise returns requested scale

  }, {
    key: "getConstrainedScale",
    value: function getConstrainedScale(requestedScale, tolerance) {
      var lowerBoundFactor = 1.0 - tolerance;
      var upperBoundFactor = 1.0 + tolerance;
      return (0, _Utils.constrain)((0, _Utils.getMinScale)(this.state, this.props) * lowerBoundFactor, this.props.maxScale * upperBoundFactor, requestedScale);
    } //Returns constrained transform when requested transform is outside constraints with tolerance, otherwise returns null

  }, {
    key: "getCorrectedTransform",
    value: function getCorrectedTransform(requestedTransform, tolerance) {
      var scale = this.getConstrainedScale(requestedTransform.scale, tolerance); //get dimensions by which scaled image overflows container

      var negativeSpace = this.calculateNegativeSpace(scale);
      var overflow = {
        width: Math.max(0, (0, _Utils.negate)(negativeSpace.width)),
        height: Math.max(0, (0, _Utils.negate)(negativeSpace.height))
      }; //if image overflows container, prevent moving by more than the overflow
      //example: overflow.height = 100, tolerance = 0.05 => top is constrained between -105 and +5

      var _this$props = this.props,
          position = _this$props.position,
          initialTop = _this$props.initialTop,
          initialLeft = _this$props.initialLeft;
      var _this$state2 = this.state,
          imageDimensions = _this$state2.imageDimensions,
          containerDimensions = _this$state2.containerDimensions;
      var upperBoundFactor = 1.0 + tolerance;
      var top = overflow.height ? (0, _Utils.constrain)((0, _Utils.negate)(overflow.height) * upperBoundFactor, overflow.height * upperBoundFactor - overflow.height, requestedTransform.top) : position === 'center' ? (containerDimensions.height - imageDimensions.height * scale) / 2 : initialTop || 0;
      var left = overflow.width ? (0, _Utils.constrain)((0, _Utils.negate)(overflow.width) * upperBoundFactor, overflow.width * upperBoundFactor - overflow.width, requestedTransform.left) : position === 'center' ? (containerDimensions.width - imageDimensions.width * scale) / 2 : initialLeft || 0;
      var constrainedTransform = {
        top: top,
        left: left,
        scale: scale
      };
      return (0, _Utils.isEqualTransform)(constrainedTransform, requestedTransform) ? null : constrainedTransform;
    } //Ensure current transform is within constraints

  }, {
    key: "maybeAdjustCurrentTransform",
    value: function maybeAdjustCurrentTransform() {
      var speed = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : 0;
      var correctedTransform;

      if (correctedTransform = this.getCorrectedTransform(this.state, 0)) {
        this.applyTransform(correctedTransform, speed);
      }
    }
  }, {
    key: "applyInitialTransform",
    value: function applyInitialTransform() {
      var speed = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : 0;
      var _this$state3 = this.state,
          imageDimensions = _this$state3.imageDimensions,
          containerDimensions = _this$state3.containerDimensions;
      var _this$props2 = this.props,
          position = _this$props2.position,
          initialScale = _this$props2.initialScale,
          maxScale = _this$props2.maxScale,
          initialTop = _this$props2.initialTop,
          initialLeft = _this$props2.initialLeft;
      var scale = String(initialScale).toLowerCase() === 'auto' ? (0, _Utils.getAutofitScale)(containerDimensions, imageDimensions) : initialScale;
      var minScale = (0, _Utils.getMinScale)(this.state, this.props);

      if (minScale > maxScale) {
        (0, _warning.default)(false, 'minScale cannot exceed maxScale.');
        return;
      }

      if (scale < minScale || scale > maxScale) {
        (0, _warning.default)(false, 'initialScale must be between minScale and maxScale.');
        return;
      }

      var initialPosition;

      if (position === 'center') {
        (0, _warning.default)(initialTop === undefined, 'initialTop prop should not be supplied with position=center. It was ignored.');
        (0, _warning.default)(initialLeft === undefined, 'initialLeft prop should not be supplied with position=center. It was ignored.');
        initialPosition = {
          top: (containerDimensions.width - imageDimensions.width * scale) / 2,
          left: (containerDimensions.height - imageDimensions.height * scale) / 2
        };
      } else {
        initialPosition = {
          top: initialTop || 0,
          left: initialLeft || 0
        };
      }

      this.constrainAndApplyTransform(initialPosition.top, initialPosition.left, scale, 0, speed);
    } //lifecycle methods

  }, {
    key: "render",
    value: function render() {
      var childElement = _react.default.Children.only(this.props.children);

      var _this$props3 = this.props,
          zoomButtons = _this$props3.zoomButtons,
          maxScale = _this$props3.maxScale,
          debug = _this$props3.debug;
      var scale = this.state.scale;
      var touchAction = this.controlOverscrollViaCss ? browserPanActions(this.state) || 'none' : undefined;
      var containerStyle = {
        width: '100%',
        height: '100%',
        overflow: 'hidden',
        touchAction: touchAction
      };
      return _react.default.createElement("div", {
        style: containerStyle
      }, zoomButtons && this.isImageReady && this.isTransformInitialized && _react.default.createElement(_ZoomButtons.default, {
        scale: scale,
        minScale: (0, _Utils.getMinScale)(this.state, this.props),
        maxScale: maxScale,
        onZoomOutClick: this.handleZoomOutClick,
        onZoomInClick: this.handleZoomInClick
      }), debug && _react.default.createElement(_StateDebugView.default, _extends({}, this.state, {
        overflow: imageOverflow(this.state)
      })), _react.default.cloneElement(childElement, {
        onTouchStart: this.handleTouchStart,
        onTouchEnd: this.handleTouchEnd,
        onMouseDown: this.handleMouseDown,
        onMouseMove: this.handleMouseMove,
        onDoubleClick: this.handleMouseDoubleClick,
        onWheel: this.handleMouseWheel,
        onDragStart: _Utils.tryCancelEvent,
        onLoad: this.handleImageLoad,
        onContextMenu: _Utils.tryCancelEvent,
        ref: this.handleRefImage,
        style: imageStyle(this.state)
      }));
    }
  }, {
    key: "componentDidMount",
    value: function componentDidMount() {
      window.addEventListener("resize", this.handleWindowResize);
      this.maybeHandleDimensionsChanged();
    }
  }, {
    key: "componentDidUpdate",
    value: function componentDidUpdate(prevProps, prevState) {
      this.maybeHandleDimensionsChanged();
    }
  }, {
    key: "componentWillUnmount",
    value: function componentWillUnmount() {
      this.cancelAnimation();
      this.imageRef.removeEventListener('touchmove', this.handleTouchMove);
      window.removeEventListener('resize', this.handleWindowResize);
    }
  }, {
    key: "calculateNegativeSpace",
    value: function calculateNegativeSpace(scale) {
      //get difference in dimension between container and scaled image
      var _this$state4 = this.state,
          containerDimensions = _this$state4.containerDimensions,
          imageDimensions = _this$state4.imageDimensions;
      var width = containerDimensions.width - scale * imageDimensions.width;
      var height = containerDimensions.height - scale * imageDimensions.height;
      return {
        width: width,
        height: height
      };
    }
  }, {
    key: "cancelAnimation",
    value: function cancelAnimation() {
      if (this.animation) {
        cancelAnimationFrame(this.animation);
      }
    }
  }, {
    key: "debug",
    value: function debug(message) {
      if (this.props.debug) {
        console.log(message);
      }
    }
  }, {
    key: "isImageReady",
    get: function get() {
      return this.isImageLoaded || this.imageRef && this.imageRef.tagName !== 'IMG';
    }
  }, {
    key: "isTransformInitialized",
    get: function get() {
      return isInitialized(this.state.top, this.state.left, this.state.scale);
    }
  }, {
    key: "controlOverscrollViaCss",
    get: function get() {
      return CSS && CSS.supports('touch-action', 'pan-up');
    }
  }], [{
    key: "getDerivedStateFromProps",
    value: function getDerivedStateFromProps(nextProps, prevState) {
      if (nextProps.initialTop !== prevState.initialTop || nextProps.initialLeft !== prevState.initialLeft || nextProps.initialScale !== prevState.initialScale || nextProps.position !== prevState.position) {
        return {
          position: nextProps.position,
          initialScale: nextProps.initialScale,
          initialTop: nextProps.initialTop,
          initialLeft: nextProps.initialLeft
        };
      } else {
        return null;
      }
    }
  }]);

  return PinchZoomPan;
}(_react.default.Component);

exports.default = PinchZoomPan;
PinchZoomPan.defaultProps = {
  initialScale: 'auto',
  minScale: 'auto',
  maxScale: 1,
  position: 'topLeft',
  zoomButtons: true,
  doubleTapBehavior: 'reset'
};
PinchZoomPan.propTypes = {
  children: _propTypes.default.element.isRequired,
  initialScale: _propTypes.default.oneOfType([_propTypes.default.number, _propTypes.default.string]),
  minScale: _propTypes.default.oneOfType([_propTypes.default.number, _propTypes.default.string]),
  maxScale: _propTypes.default.number,
  position: _propTypes.default.oneOf(['topLeft', 'center']),
  zoomButtons: _propTypes.default.bool,
  doubleTapBehavior: _propTypes.default.oneOf(['reset', 'zoom']),
  initialTop: _propTypes.default.number,
  initialLeft: _propTypes.default.number
};