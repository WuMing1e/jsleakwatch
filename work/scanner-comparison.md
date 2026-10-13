# 整站扫描器对比 · 语料 demo（9 个资产，标注 tp 19 / fp 2）

| 工具 | 命中 | TP | FP | 未归类 | 漏报 | 精确率 | 召回率 | F1 |
|---|---|---|---|---|---|---|---|---|
| JSLeakWatch | 20 | 18 | 2 | 0 | 1 | 0.900 | 0.947 | 0.923 |
| JSHawk | 5 | 5 | 0 | 0 | 14 | 1.000 | 0.263 | 0.417 |
| JScanner2 | 6 | 6 | 0 | 0 | 13 | 1.000 | 0.316 | 0.480 |

## 所有工具都没检出的标注（1 条）

- PostHog 项目密钥 (两套规则都未覆盖)

## 只有部分工具检出（17 条）

- amap-key | b7e4...d807(len=32) — 检出: JSLeakWatch
- env-var-leak | 8f3a...c4d5(len=32) — 检出: JSLeakWatch
- google-api-key | AIza...I6jK(len=39) — 检出: JSHawk, JSLeakWatch
- stripe-secret-key | sk_l...EyU6(len=40) — 检出: JSHawk, JSLeakWatch
- aliyun-access-key-id | LTAI...qW3F(len=24) — 检出: JSLeakWatch, JScanner2
- aliyun-access-key-secret | kR8m...c3Jf(len=29) — 检出: JSLeakWatch, JScanner2
- tencent-cloud-secret-id | AKID...hESA(len=36) — 检出: JSLeakWatch, JScanner2
- amap-key | 3f8c...6c04(len=32) — 检出: JSLeakWatch, JScanner2
- wechat-appsecret | d41f...8a35(len=32) — 检出: JSLeakWatch, JScanner2
- database-url | redi...79/0(len=49) — 检出: JSHawk, JSLeakWatch
- jwt-token | eyJh...QmZs(len=151) — 检出: JSHawk, JSLeakWatch
- stripe-secret-key | sk_l...zV7W(len=41) — 检出: JSLeakWatch
- stripe-webhook-secret | whse...2084(len=38) — 检出: JSLeakWatch
- feishu-webhook | http...5e6f(len=81) — 检出: JSLeakWatch
- dingtalk-webhook | http...0b1c(len=114) — 检出: JSLeakWatch
- aws-access-key-id | AKIA...D4PA(len=20) — 检出: JSLeakWatch
- mailgun-api-key | 7c1e...2084(len=32) — 检出: JSLeakWatch
