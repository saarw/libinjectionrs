#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttributeType {
    None,
    Black,
    AttrUrl, 
    Style,
    AttrIndirect,
}

pub struct StringType {
    pub name: &'static str,
    pub atype: AttributeType,
}

// Hex decode map for HTML entity decoding
pub const HEX_DECODE_MAP: [i32; 256] = [
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    0,   1,   2,   3,   4,   5,   6,   7,   8,   9,   256, 256, 256, 256, 256, 256,
    256, 10,  11,  12,  13,  14,  15,  256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 10,  11,  12,  13,  14,  15,  256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
];

// Event handler attributes (on* events)
pub const BLACK_ATTR_EVENTS: &[StringType] = &[
    StringType { name: "ABORT", atype: AttributeType::Black },
    StringType { name: "ACTIVATE", atype: AttributeType::Black },
    StringType { name: "ACTIVE", atype: AttributeType::Black },
    StringType { name: "ADDSOURCEBUFFER", atype: AttributeType::Black },
    StringType { name: "ADDSTREAM", atype: AttributeType::Black },
    StringType { name: "ADDTRACK", atype: AttributeType::Black },
    StringType { name: "AFTERPRINT", atype: AttributeType::Black },
    StringType { name: "ANIMATIONCANCEL", atype: AttributeType::Black },
    StringType { name: "ANIMATIONEND", atype: AttributeType::Black },
    StringType { name: "ANIMATIONITERATION", atype: AttributeType::Black },
    StringType { name: "ANIMATIONSTART", atype: AttributeType::Black },
    StringType { name: "AUDIOEND", atype: AttributeType::Black },
    StringType { name: "AUDIOPROCESS", atype: AttributeType::Black },
    StringType { name: "AUDIOSTART", atype: AttributeType::Black },
    StringType { name: "AUTOCOMPLETEERROR", atype: AttributeType::Black },
    StringType { name: "AUTOCOMPLETE", atype: AttributeType::Black },
    StringType { name: "BEFOREACTIVATE", atype: AttributeType::Black },
    StringType { name: "BEFORECOPY", atype: AttributeType::Black },
    StringType { name: "BEFORECUT", atype: AttributeType::Black },
    StringType { name: "BEFOREINPUT", atype: AttributeType::Black },
    StringType { name: "BEFORELOAD", atype: AttributeType::Black },
    StringType { name: "BEFOREPASTE", atype: AttributeType::Black },
    StringType { name: "BEFOREPRINT", atype: AttributeType::Black },
    StringType { name: "BEFOREUNLOAD", atype: AttributeType::Black },
    StringType { name: "BEGINEVENT", atype: AttributeType::Black },
    StringType { name: "BLOCKED", atype: AttributeType::Black },
    StringType { name: "BLUR", atype: AttributeType::Black },
    StringType { name: "BOUNDARY", atype: AttributeType::Black },
    StringType { name: "BUFFEREDAMOUNTLOW", atype: AttributeType::Black },
    StringType { name: "CACHED", atype: AttributeType::Black },
    StringType { name: "CANCEL", atype: AttributeType::Black },
    StringType { name: "CANPLAYTHROUGH", atype: AttributeType::Black },
    StringType { name: "CANPLAY", atype: AttributeType::Black },
    StringType { name: "CHANGE", atype: AttributeType::Black },
    StringType { name: "CHARGINGCHANGE", atype: AttributeType::Black },
    StringType { name: "CHARGINGTIMECHANGE", atype: AttributeType::Black },
    StringType { name: "CHECKING", atype: AttributeType::Black },
    StringType { name: "CLICK", atype: AttributeType::Black },
    StringType { name: "CLOSE", atype: AttributeType::Black },
    StringType { name: "COMPLETE", atype: AttributeType::Black },
    StringType { name: "COMPOSITIONEND", atype: AttributeType::Black },
    StringType { name: "COMPOSITIONSTART", atype: AttributeType::Black },
    StringType { name: "COMPOSITIONUPDATE", atype: AttributeType::Black },
    StringType { name: "CONNECTING", atype: AttributeType::Black },
    StringType { name: "CONNECTIONSTATECHANGE", atype: AttributeType::Black },
    StringType { name: "CONNECT", atype: AttributeType::Black },
    StringType { name: "CONTEXTMENU", atype: AttributeType::Black },
    StringType { name: "CONTROLLERCHANGE", atype: AttributeType::Black },
    StringType { name: "COPY", atype: AttributeType::Black },
    StringType { name: "CUECHANGE", atype: AttributeType::Black },
    StringType { name: "CUT", atype: AttributeType::Black },
    StringType { name: "DATAAVAILABLE", atype: AttributeType::Black },
    StringType { name: "DATACHANNEL", atype: AttributeType::Black },
    StringType { name: "DBLCLICK", atype: AttributeType::Black },
    StringType { name: "DEVICECHANGE", atype: AttributeType::Black },
    StringType { name: "DEVICEMOTION", atype: AttributeType::Black },
    StringType { name: "DEVICEORIENTATION", atype: AttributeType::Black },
    StringType { name: "DISCHARGINGTIMECHANGE", atype: AttributeType::Black },
    StringType { name: "DISCONNECT", atype: AttributeType::Black },
    StringType { name: "DOMACTIVATE", atype: AttributeType::Black },
    StringType { name: "DOMCHARACTERDATAMODIFIED", atype: AttributeType::Black },
    StringType { name: "DOMCONTENTLOADED", atype: AttributeType::Black },
    StringType { name: "DOMFOCUSIN", atype: AttributeType::Black },
    StringType { name: "DOMFOCUSOUT", atype: AttributeType::Black },
    StringType { name: "DOMNODEINSERTEDINTODOCUMENT", atype: AttributeType::Black },
    StringType { name: "DOMNODEINSERTED", atype: AttributeType::Black },
    StringType { name: "DOMNODEREMOVEDFROMDOCUMENT", atype: AttributeType::Black },
    StringType { name: "DOMNODEREMOVED", atype: AttributeType::Black },
    StringType { name: "DOMSUBTREEMODIFIED", atype: AttributeType::Black },
    StringType { name: "DOWNLOADING", atype: AttributeType::Black },
    StringType { name: "DRAGEND", atype: AttributeType::Black },
    StringType { name: "DRAGENTER", atype: AttributeType::Black },
    StringType { name: "DRAGLEAVE", atype: AttributeType::Black },
    StringType { name: "DRAGOVER", atype: AttributeType::Black },
    StringType { name: "DRAGSTART", atype: AttributeType::Black },
    StringType { name: "DRAG", atype: AttributeType::Black },
    StringType { name: "DROP", atype: AttributeType::Black },
    StringType { name: "DURATIONCHANGE", atype: AttributeType::Black },
    StringType { name: "EMPTIED", atype: AttributeType::Black },
    StringType { name: "ENCRYPTED", atype: AttributeType::Black },
    StringType { name: "ENDED", atype: AttributeType::Black },
    StringType { name: "ENDEVENT", atype: AttributeType::Black },
    StringType { name: "END", atype: AttributeType::Black },
    StringType { name: "ENTERPICTUREINPICTURE", atype: AttributeType::Black },
    StringType { name: "ENTER", atype: AttributeType::Black },
    StringType { name: "ERROR", atype: AttributeType::Black },
    StringType { name: "EXIT", atype: AttributeType::Black },
    StringType { name: "FETCH", atype: AttributeType::Black },
    StringType { name: "FINISH", atype: AttributeType::Black },
    StringType { name: "FOCUSIN", atype: AttributeType::Black },
    StringType { name: "FOCUSOUT", atype: AttributeType::Black },
    StringType { name: "FOCUS", atype: AttributeType::Black },
    StringType { name: "FORMCHANGE", atype: AttributeType::Black },
    StringType { name: "FORMINPUT", atype: AttributeType::Black },
    StringType { name: "GAMEPADCONNECTED", atype: AttributeType::Black },
    StringType { name: "GAMEPADDISCONNECTED", atype: AttributeType::Black },
    StringType { name: "GESTURECHANGE", atype: AttributeType::Black },
    StringType { name: "GESTUREEND", atype: AttributeType::Black },
    StringType { name: "GESTURESCROLLEND", atype: AttributeType::Black },
    StringType { name: "GESTURESCROLLSTART", atype: AttributeType::Black },
    StringType { name: "GESTURESCROLLUPDATE", atype: AttributeType::Black },
    StringType { name: "GESTURESTART", atype: AttributeType::Black },
    StringType { name: "GESTURETAPDOWN", atype: AttributeType::Black },
    StringType { name: "GESTURETAP", atype: AttributeType::Black },
    StringType { name: "GOTPOINTERCAPTURE", atype: AttributeType::Black },
    StringType { name: "HASHCHANGE", atype: AttributeType::Black },
    StringType { name: "ICECANDIDATEERROR", atype: AttributeType::Black },
    StringType { name: "ICECANDIDATE", atype: AttributeType::Black },
    StringType { name: "ICECONNECTIONSTATECHANGE", atype: AttributeType::Black },
    StringType { name: "ICEGATHERINGSTATECHANGE", atype: AttributeType::Black },
    StringType { name: "INACTIVE", atype: AttributeType::Black },
    StringType { name: "INPUTSOURCESCHANGE", atype: AttributeType::Black },
    StringType { name: "INPUT", atype: AttributeType::Black },
    StringType { name: "INSTALL", atype: AttributeType::Black },
    StringType { name: "INVALID", atype: AttributeType::Black },
    StringType { name: "KEYDOWN", atype: AttributeType::Black },
    StringType { name: "KEYPRESS", atype: AttributeType::Black },
    StringType { name: "KEYSTATUSESCHANGE", atype: AttributeType::Black },
    StringType { name: "KEYUP", atype: AttributeType::Black },
    StringType { name: "LANGUAGECHANGE", atype: AttributeType::Black },
    StringType { name: "LEAVEPICTUREINPICTURE", atype: AttributeType::Black },
    StringType { name: "LEVELCHANGE", atype: AttributeType::Black },
    StringType { name: "LOADEDDATA", atype: AttributeType::Black },
    StringType { name: "LOADEDMETADATA", atype: AttributeType::Black },
    StringType { name: "LOADEND", atype: AttributeType::Black },
    StringType { name: "LOADINGDONE", atype: AttributeType::Black },
    StringType { name: "LOADINGERROR", atype: AttributeType::Black },
    StringType { name: "LOADING", atype: AttributeType::Black },
    StringType { name: "LOADSTART", atype: AttributeType::Black },
    StringType { name: "LOAD", atype: AttributeType::Black },
    StringType { name: "LOSTPOINTERCAPTURE", atype: AttributeType::Black },
    StringType { name: "MARK", atype: AttributeType::Black },
    StringType { name: "MERCHANTVALIDATION", atype: AttributeType::Black },
    StringType { name: "MESSAGEERROR", atype: AttributeType::Black },
    StringType { name: "MESSAGE", atype: AttributeType::Black },
    StringType { name: "MOUSEDOWN", atype: AttributeType::Black },
    StringType { name: "MOUSEENTER", atype: AttributeType::Black },
    StringType { name: "MOUSELEAVE", atype: AttributeType::Black },
    StringType { name: "MOUSEMOVE", atype: AttributeType::Black },
    StringType { name: "MOUSEOUT", atype: AttributeType::Black },
    StringType { name: "MOUSEOVER", atype: AttributeType::Black },
    StringType { name: "MOUSEUP", atype: AttributeType::Black },
    StringType { name: "MOUSEWHEEL", atype: AttributeType::Black },
    StringType { name: "MUTE", atype: AttributeType::Black },
    StringType { name: "NEGOTIATIONNEEDED", atype: AttributeType::Black },
    StringType { name: "NEXTTRACK", atype: AttributeType::Black },
    StringType { name: "NOMATCH", atype: AttributeType::Black },
    StringType { name: "NOUPDATE", atype: AttributeType::Black },
    StringType { name: "OBSOLETE", atype: AttributeType::Black },
    StringType { name: "OFFLINE", atype: AttributeType::Black },
    StringType { name: "ONLINE", atype: AttributeType::Black },
    StringType { name: "OPEN", atype: AttributeType::Black },
    StringType { name: "ORIENTATIONCHANGE", atype: AttributeType::Black },
    StringType { name: "OVERCONSTRAINED", atype: AttributeType::Black },
    StringType { name: "OVERFLOWCHANGED", atype: AttributeType::Black },
    StringType { name: "PAGEHIDE", atype: AttributeType::Black },
    StringType { name: "PAGESHOW", atype: AttributeType::Black },
    StringType { name: "PASTE", atype: AttributeType::Black },
    StringType { name: "PAUSE", atype: AttributeType::Black },
    StringType { name: "PAYERDETAILCHANGE", atype: AttributeType::Black },
    StringType { name: "PAYMENTAUTHORIZED", atype: AttributeType::Black },
    StringType { name: "PAYMENTMETHODCHANGE", atype: AttributeType::Black },
    StringType { name: "PAYMENTMETHODSELECTED", atype: AttributeType::Black },
    StringType { name: "PLAYING", atype: AttributeType::Black },
    StringType { name: "PLAY", atype: AttributeType::Black },
    StringType { name: "POINTERCANCEL", atype: AttributeType::Black },
    StringType { name: "POINTERDOWN", atype: AttributeType::Black },
    StringType { name: "POINTERENTER", atype: AttributeType::Black },
    StringType { name: "POINTERLEAVE", atype: AttributeType::Black },
    StringType { name: "POINTERLOCKCHANGE", atype: AttributeType::Black },
    StringType { name: "POINTERLOCKERROR", atype: AttributeType::Black },
    StringType { name: "POINTERMOVE", atype: AttributeType::Black },
    StringType { name: "POINTEROUT", atype: AttributeType::Black },
    StringType { name: "POINTEROVER", atype: AttributeType::Black },
    StringType { name: "POINTERUP", atype: AttributeType::Black },
    StringType { name: "POPSTATE", atype: AttributeType::Black },
    StringType { name: "PREVIOUSTRACK", atype: AttributeType::Black },
    StringType { name: "PROCESSORERROR", atype: AttributeType::Black },
    StringType { name: "PROGRESS", atype: AttributeType::Black },
    StringType { name: "PROPERTYCHANGE", atype: AttributeType::Black },
    StringType { name: "RATECHANGE", atype: AttributeType::Black },
    StringType { name: "READYSTATECHANGE", atype: AttributeType::Black },
    StringType { name: "REJECTIONHANDLED", atype: AttributeType::Black },
    StringType { name: "REMOVESOURCEBUFFER", atype: AttributeType::Black },
    StringType { name: "REMOVESTREAM", atype: AttributeType::Black },
    StringType { name: "REMOVETRACK", atype: AttributeType::Black },
    StringType { name: "REMOVE", atype: AttributeType::Black },
    StringType { name: "RESET", atype: AttributeType::Black },
    StringType { name: "RESIZE", atype: AttributeType::Black },
    StringType { name: "RESOURCETIMINGBUFFERFULL", atype: AttributeType::Black },
    StringType { name: "RESULT", atype: AttributeType::Black },
    StringType { name: "RESUME", atype: AttributeType::Black },
    StringType { name: "SCROLL", atype: AttributeType::Black },
    StringType { name: "SEARCH", atype: AttributeType::Black },
    StringType { name: "SECURITYPOLICYVIOLATION", atype: AttributeType::Black },
    StringType { name: "SEEKED", atype: AttributeType::Black },
    StringType { name: "SEEKING", atype: AttributeType::Black },
    StringType { name: "SELECTEND", atype: AttributeType::Black },
    StringType { name: "SELECTIONCHANGE", atype: AttributeType::Black },
    StringType { name: "SELECTSTART", atype: AttributeType::Black },
    StringType { name: "SELECT", atype: AttributeType::Black },
    StringType { name: "SHIPPINGADDRESSCHANGE", atype: AttributeType::Black },
    StringType { name: "SHIPPINGCONTACTSELECTED", atype: AttributeType::Black },
    StringType { name: "SHIPPINGMETHODSELECTED", atype: AttributeType::Black },
    StringType { name: "SHIPPINGOPTIONCHANGE", atype: AttributeType::Black },
    StringType { name: "SHOW", atype: AttributeType::Black },
    StringType { name: "SIGNALINGSTATECHANGE", atype: AttributeType::Black },
    StringType { name: "SLOTCHANGE", atype: AttributeType::Black },
    StringType { name: "SOUNDEND", atype: AttributeType::Black },
    StringType { name: "SOUNDSTART", atype: AttributeType::Black },
    StringType { name: "SOURCECLOSE", atype: AttributeType::Black },
    StringType { name: "SOURCEENDED", atype: AttributeType::Black },
    StringType { name: "SOURCEOPEN", atype: AttributeType::Black },
    StringType { name: "SPEECHEND", atype: AttributeType::Black },
    StringType { name: "SPEECHSTART", atype: AttributeType::Black },
    StringType { name: "SQUEEZEEND", atype: AttributeType::Black },
    StringType { name: "SQUEEZESTART", atype: AttributeType::Black },
    StringType { name: "SQUEEZE", atype: AttributeType::Black },
    StringType { name: "STALLED", atype: AttributeType::Black },
    StringType { name: "STARTED", atype: AttributeType::Black },
    StringType { name: "START", atype: AttributeType::Black },
    StringType { name: "STATECHANGE", atype: AttributeType::Black },
    StringType { name: "STOP", atype: AttributeType::Black },
    StringType { name: "STORAGE", atype: AttributeType::Black },
    StringType { name: "SUBMIT", atype: AttributeType::Black },
    StringType { name: "SUCCESS", atype: AttributeType::Black },
    StringType { name: "SUSPEND", atype: AttributeType::Black },
    StringType { name: "TEXTINPUT", atype: AttributeType::Black },
    StringType { name: "TIMEOUT", atype: AttributeType::Black },
    StringType { name: "TIMEUPDATE", atype: AttributeType::Black },
    StringType { name: "TOGGLE", atype: AttributeType::Black },
    StringType { name: "TONECHANGE", atype: AttributeType::Black },
    StringType { name: "TOUCHCANCEL", atype: AttributeType::Black },
    StringType { name: "TOUCHEND", atype: AttributeType::Black },
    StringType { name: "TOUCHFORCECHANGE", atype: AttributeType::Black },
    StringType { name: "TOUCHMOVE", atype: AttributeType::Black },
    StringType { name: "TOUCHSTART", atype: AttributeType::Black },
    StringType { name: "TRACK", atype: AttributeType::Black },
    StringType { name: "TRANSITIONCANCEL", atype: AttributeType::Black },
    StringType { name: "TRANSITIONEND", atype: AttributeType::Black },
    StringType { name: "TRANSITIONRUN", atype: AttributeType::Black },
    StringType { name: "TRANSITIONSTART", atype: AttributeType::Black },
    StringType { name: "UNCAPTUREDERROR", atype: AttributeType::Black },
    StringType { name: "UNHANDLEDREJECTION", atype: AttributeType::Black },
    StringType { name: "UNLOAD", atype: AttributeType::Black },
    StringType { name: "UNMUTE", atype: AttributeType::Black },
    StringType { name: "UPDATEEND", atype: AttributeType::Black },
    StringType { name: "UPDATEFOUND", atype: AttributeType::Black },
    StringType { name: "UPDATEREADY", atype: AttributeType::Black },
    StringType { name: "UPDATESTART", atype: AttributeType::Black },
    StringType { name: "UPDATE", atype: AttributeType::Black },
    StringType { name: "UPGRADENEEDED", atype: AttributeType::Black },
    StringType { name: "VALIDATEMERCHANT", atype: AttributeType::Black },
    StringType { name: "VERSIONCHANGE", atype: AttributeType::Black },
    StringType { name: "VISIBILITYCHANGE", atype: AttributeType::Black },
    StringType { name: "VOLUMECHANGE", atype: AttributeType::Black },
    StringType { name: "WAITINGFORKEY", atype: AttributeType::Black },
    StringType { name: "WAITING", atype: AttributeType::Black },
    StringType { name: "WEBGLCONTEXTCHANGED", atype: AttributeType::Black },
    StringType { name: "WEBGLCONTEXTCREATIONERROR", atype: AttributeType::Black },
    StringType { name: "WEBGLCONTEXTLOST", atype: AttributeType::Black },
    StringType { name: "WEBGLCONTEXTRESTORED", atype: AttributeType::Black },
    StringType { name: "WEBKITANIMATIONEND", atype: AttributeType::Black },
    StringType { name: "WEBKITANIMATIONITERATION", atype: AttributeType::Black },
    StringType { name: "WEBKITANIMATIONSTART", atype: AttributeType::Black },
    StringType { name: "WEBKITBEFORETEXTINSERTED", atype: AttributeType::Black },
    StringType { name: "WEBKITBEGINFULLSCREEN", atype: AttributeType::Black },
    StringType { name: "WEBKITCURRENTPLAYBACKTARGETISWIRELESSCHANGED", atype: AttributeType::Black },
    StringType { name: "WEBKITENDFULLSCREEN", atype: AttributeType::Black },
    StringType { name: "WEBKITFULLSCREENCHANGE", atype: AttributeType::Black },
    StringType { name: "WEBKITFULLSCREENERROR", atype: AttributeType::Black },
    StringType { name: "WEBKITKEYADDED", atype: AttributeType::Black },
    StringType { name: "WEBKITKEYERROR", atype: AttributeType::Black },
    StringType { name: "WEBKITKEYMESSAGE", atype: AttributeType::Black },
    StringType { name: "WEBKITMOUSEFORCECHANGED", atype: AttributeType::Black },
    StringType { name: "WEBKITMOUSEFORCEDOWN", atype: AttributeType::Black },
    StringType { name: "WEBKITMOUSEFORCEUP", atype: AttributeType::Black },
    StringType { name: "WEBKITMOUSEFORCEWILLBEGIN", atype: AttributeType::Black },
    StringType { name: "WEBKITNEEDKEY", atype: AttributeType::Black },
    StringType { name: "WEBKITNETWORKINFOCHANGE", atype: AttributeType::Black },
    StringType { name: "WEBKITPLAYBACKTARGETAVAILABILITYCHANGED", atype: AttributeType::Black },
    StringType { name: "WEBKITPRESENTATIONMODECHANGED", atype: AttributeType::Black },
    StringType { name: "WEBKITREGIONOVERSETCHANGE", atype: AttributeType::Black },
    StringType { name: "WEBKITREMOVESOURCEBUFFER", atype: AttributeType::Black },
    StringType { name: "WEBKITSOURCECLOSE", atype: AttributeType::Black },
    StringType { name: "WEBKITSOURCEENDED", atype: AttributeType::Black },
    StringType { name: "WEBKITSOURCEOPEN", atype: AttributeType::Black },
    StringType { name: "WEBKITSPEECHCHANGE", atype: AttributeType::Black },
    StringType { name: "WEBKITTRANSITIONEND", atype: AttributeType::Black },
    StringType { name: "WEBKITWILLREVEALBOTTOM", atype: AttributeType::Black },
    StringType { name: "WEBKITWILLREVEALLEFT", atype: AttributeType::Black },
    StringType { name: "WEBKITWILLREVEALRIGHT", atype: AttributeType::Black },
    StringType { name: "WEBKITWILLREVEALTOP", atype: AttributeType::Black },
    StringType { name: "WHEEL", atype: AttributeType::Black },
    StringType { name: "WRITEEND", atype: AttributeType::Black },
    StringType { name: "WRITESTART", atype: AttributeType::Black },
    StringType { name: "WRITE", atype: AttributeType::Black },
    StringType { name: "ZOOM", atype: AttributeType::Black },
];

// Other dangerous attributes
pub const BLACK_ATTRS: &[StringType] = &[
    StringType { name: "ACTION", atype: AttributeType::AttrUrl },
    StringType { name: "ATTRIBUTENAME", atype: AttributeType::AttrIndirect },
    StringType { name: "BY", atype: AttributeType::AttrUrl },
    StringType { name: "BACKGROUND", atype: AttributeType::AttrUrl },
    StringType { name: "DATAFORMATAS", atype: AttributeType::Black },
    StringType { name: "DATASRC", atype: AttributeType::Black },
    StringType { name: "DYNSRC", atype: AttributeType::AttrUrl },
    StringType { name: "FILTER", atype: AttributeType::Style },
    StringType { name: "FORMACTION", atype: AttributeType::AttrUrl },
    StringType { name: "FOLDER", atype: AttributeType::AttrUrl },
    StringType { name: "FROM", atype: AttributeType::AttrUrl },
    StringType { name: "HANDLER", atype: AttributeType::AttrUrl },
    StringType { name: "HREF", atype: AttributeType::AttrUrl },
    StringType { name: "LOWSRC", atype: AttributeType::AttrUrl },
    StringType { name: "POSTER", atype: AttributeType::AttrUrl },
    StringType { name: "SRC", atype: AttributeType::AttrUrl },
    StringType { name: "STYLE", atype: AttributeType::Style },
    StringType { name: "TO", atype: AttributeType::AttrUrl },
    StringType { name: "VALUES", atype: AttributeType::AttrUrl },
    StringType { name: "XLINK:HREF", atype: AttributeType::AttrUrl },
];

// Dangerous HTML tags
pub const BLACK_TAGS: &[&str] = &[
    "APPLET",
    "BASE",
    "COMMENT",
    "EMBED", 
    "FRAME",
    "FRAMESET",
    "HANDLER",
    "IFRAME",
    "IMPORT",
    "ISINDEX",
    "LINK",
    "LISTENER",
    "META",
    "NOSCRIPT",
    "OBJECT",
    "SCRIPT",
    "STYLE",
    "VMLFRAME",
    "XML",
    "XSS",
];

// Dangerous URL protocols
pub const BLACK_URL_PROTOCOLS: &[&str] = &[
    "DATA",
    "VIEW-SOURCE", 
    "VBSCRIPT",
    "JAVA", // covers JAVA, JAVASCRIPT
];

pub fn html_decode_char_at(src: &[u8], consumed: &mut usize) -> i32 {
    if src.is_empty() {
        *consumed = 0;
        return -1;
    }

    *consumed = 1;
    if src[0] != b'&' || src.len() < 2 {
        return src[0] as i32;
    }

    if src[1] != b'#' {
        // Named entities - we don't handle them for XSS detection
        return b'&' as i32;
    }

    if src.len() > 2 && (src[2] == b'x' || src[2] == b'X') {
        // Hexadecimal entity
        if src.len() < 4 {
            return b'&' as i32;
        }
        
        let ch = HEX_DECODE_MAP[src[3] as usize];
        if ch == 256 {
            return b'&' as i32;
        }

        let mut val = ch;
        let mut i = 4;
        while i < src.len() {
            let ch = src[i];
            if ch == b';' {
                *consumed = i + 1;
                return val;
            }
            let ch_val = HEX_DECODE_MAP[ch as usize];
            if ch_val == 256 {
                *consumed = i;
                return val;
            }
            val = (val * 16) + ch_val;
            if val > 0x1000FF {
                return b'&' as i32;
            }
            i += 1;
        }
        *consumed = i;
        val
    } else {
        // Decimal entity
        let mut i = 2;
        if i >= src.len() {
            return b'&' as i32;
        }
        
        let ch = src[i];
        if ch < b'0' || ch > b'9' {
            return b'&' as i32;
        }
        
        let mut val = (ch - b'0') as i32;
        i += 1;
        while i < src.len() {
            let ch = src[i];
            if ch == b';' {
                *consumed = i + 1;
                return val;
            }
            if ch < b'0' || ch > b'9' {
                *consumed = i;
                return val;
            }
            val = (val * 10) + ((ch - b'0') as i32);
            if val > 0x1000FF {
                return b'&' as i32;
            }
            i += 1;
        }
        *consumed = i;
        val
    }
}