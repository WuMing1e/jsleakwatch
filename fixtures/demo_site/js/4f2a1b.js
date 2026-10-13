/*! chunk 4f2a1b - 按需加载的订单模块 (密钥藏在 chunk 里, 只抓入口文件会漏掉) */
(function () {
  var payment = {
    stripeSecret: "sk_live_51QyU9nLrMq4SpZ8xX3eKgB0cId5FzV7W",
    dingtalkAlert: "https://oapi.dingtalk.com/robot/send?access_token=" +
      "3f2b8c1d4e5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c",
    feishuHook: "https://open.feishu.cn/open-apis/bot/v2/hook/9c1d2e5f-7a8b-4c3d-9e0f-1a2b3c4d5e6f",
    webhookSecret: "whsec_5a9d3f1b7c2e8046bd9f3a1c7e5b2084"
  };
  window.DemoOrder = payment;
})();
