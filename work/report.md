# 分析器对比报告 · 语料 `demo`

- 资产数: 9  |  入口: http://127.0.0.1:8899/
- 标注: tp 19 · fp 2 · 未标注 0
- 生成时间: 2026-10-11T10:58:33+00:00

| 分析器 | 命中 | TP | FP | 未标注 | 漏报 | 精确率 | 召回率 | F1 | 独有命中 | 耗时 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| builtin | 22 | 20 | 2 | 0 | 1 | 0.909 | 0.952 | 0.930 | 10 | 3 ms |
| cli:jshawk | 13 | 13 | 0 | 0 | 9 | 1.000 | 0.591 | 0.743 | 0 | 181 ms |

## 漏报明细（标注为真凭证但未全部检出）

- `http://127.0.0.1:8899/` amap-key | b7e4...d807(len=32) — 检出: builtin / 漏掉: cli:jshawk
- `http://127.0.0.1:8899/js/app.js` google-api-key | AIza...I6jK(len=39) — 检出: builtin / 漏掉: cli:jshawk
- `http://127.0.0.1:8899/js/app.js` tencent-cloud-secret-id | AKID...hESA(len=36) — 检出: builtin / 漏掉: cli:jshawk
- `http://127.0.0.1:8899/js/app.js` amap-key | 3f8c...6c04(len=32) — 检出: builtin / 漏掉: cli:jshawk
- `http://127.0.0.1:8899/js/app.js` database-url | redi...79/0(len=49) — 检出: builtin / 漏掉: cli:jshawk
- `http://127.0.0.1:8899/js/app.js` jwt-token | eyJh...QmZs(len=151) — 检出: builtin / 漏掉: cli:jshawk
- `http://127.0.0.1:8899/js/4f2a1b.js` dingtalk-webhook | http...0b1c(len=114) — 检出: builtin / 漏掉: cli:jshawk
- `http://127.0.0.1:8899/js/app.js.map` mailgun-api-key | 7c1e...2084(len=32) — 检出: builtin / 漏掉: cli:jshawk
- `http://127.0.0.1:8899/js/vendor.js` PostHog 项目密钥 (两套规则都未覆盖) — 检出: 无 / 漏掉: builtin, cli:jshawk
