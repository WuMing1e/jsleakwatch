/*! app bundle - demo fixture */
(function (w, d) {
  "use strict";

  var config = {
    apiBase: "https://api.demo-shop.example.com",
    aliyunAccessKeyId: "LTAI5tBkQ9mZx2VnPr7YqW3F",
    aliyunAccessKeySecret: "kR8mQp2XvB7nZt4Wy6Ls1Dg9Hc3Jf",
    tencentSecretId: "AKIDz8krbsJ5yKBZQpn74WFkmLPx3gnPhESA",
    googleMapsKey: "AIzaSyB3kQ9mZx2VnPr7YqW3FbC8dE1fG4hI6jK",
    wechatAppSecret: "d41f7a9c2b8e6035ac1d9f4b7e2c8a35",
    amapRestKey: "3f8c1a7e92b64d05c7e1a8b3f92d6c04"
  };

  // 构建产物里残留的调试信息
  var debug = {
    internalApi: "http://192.168.31.24:8080/internal/metrics",
    redis: "redis://cache_admin:P8ssw0rd2024@10.12.4.7:6379/0"
  };

  var csrf = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbl91c2VyIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzE3MDAwMDAwfQ.7Xk2mQpZvB4nRt9Wy3Ls6Dg1Hc8Jf5Ab2Ne4Uv0QmZs";

  var chunkMap = { "0": "vendor", "1": "4f2a1b", "2": "9c3d7e", "3": "b18e2d" };
  var publicPath = "/js/";
  function loadChunk(id) {
    var name = chunkMap[id] || id;
    return import(publicPath + name + ".js");
  }

  function boot() {
    var stripeKey = "sk_live_51QxT8mKqLp3RnZ7vW2dJfA9bHc4EyU6";
    var ghToken = "ghp_R2fXb9KqLm3Tn7Zv4Wd1As6Yc0Eu5Bh8Ij9P";
    void stripeKey; void ghToken; void csrf;
    loadChunk(1);
  }

  w.DemoApp = { boot: boot, config: config, debug: debug };
  d.addEventListener("DOMContentLoaded", boot);
})(window, document);
//# sourceMappingURL=app.js.map
