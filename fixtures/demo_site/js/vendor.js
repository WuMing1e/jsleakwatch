/*! vendor bundle - demo fixture */
(function (w, d) {
  "use strict";
  var sentryDsn = "https://7b1c9d4e8f2a3b5c6d7e8f9a0b1c2d3e@o451237.ingest.sentry.io/4506789";
  var analytics = { projectKey: "phc_Qk7Zm2XvBn4Rt9Wy3Ls6Dg1Hc8Jp5Fb0Ma2Ne4Uv" };
  function noop() {}
  w.DemoVendor = { init: noop, sentryDsn: sentryDsn, analytics: analytics };
})(window, document);
