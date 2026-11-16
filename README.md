# 多头借贷与设备聚集识别

风控发现一批新账号共享设备指纹，短时间内互相转账。

```
data/events.jsonl   3014 条交易事件（含标注欺诈，事件格式保持不变）
labels.json         欺诈事件标注
rules.py            版本化规则配置（改阈值=改数据并升版本，无需发版）
detectors.py        检测器：每条告警附带完整证据与规则版本快照
engine.py           CLI 入口，输出带版本的告警 JSON
tests/              零误报、团伙命中、家庭共用排除、版本回归测试
```

## Run

```bash
python -m pytest tests -q
python engine.py data/events.jsonl alerts.json
python engine.py data/events.jsonl alerts.json --rule shared_device_transfer_ring
```

## 规则（ruleset 1.0.0）

| 规则 | 形态 | 关键判据 |
|---|---|---|
| `shared_device_transfer_ring` | 新账号共享一批设备指纹并在短窗内互相转账 | 账号对共享指纹数 ≥2、180s 内同额转账边、≥4 账号、≥8 条边、密度 ≥0.6、整体跨度 ≤900s |
| `burst_small_pay` | 陌生区域 60s 内 12 笔小额支付 | 仅统计该账号历史未出现过的区域 |
| `new_device_big_withdraw` | 新设备登录后短时间大额提现 | 首见设备登录 + 300s 内 ≥48000 提现 |

### 团伙 vs 家庭共用设备如何区分

家庭/合租共用设备在数据上的特征是：少数指纹被零星复用、相遇跨越一两天、
账号对之间几乎没有协同转账，形成的图组件**跨度长、密度低**。
设备农场/团伙则同时满足两点：

1. **设备聚集**——每对账号都共享同一批指纹（`min_shared_fingerprints`）；
2. **资金协同**——在一个紧凑时间窗（`max_span_s`）内形成**高密度**同额转账图
   （`min_density`、`min_edges`），随机背景的稀疏长寿命组件无法同时满足。

两者取交集，单纯共享设备（家庭）或单纯时间接近的转账都不会告警。

## 告警结构

每条告警自描述，包含：

- `rule` / `rule_version` / `ruleset_version` 与完整 `params` 快照；
- `window`：触发时间窗（起止与跨度秒数）；
- `accounts`：涉案账号集合；
- `devices`：窗口内设备、共享指纹批次、团伙指纹全集；
- `transfer_edges`：每条转账边（双方账号、金额、两个时间戳、间隔、双方设备、共享指纹）；
- `evidence_events`：回溯到事件文件行号的原始事件；
- `metrics`：账号数、边数、图密度等量化指标。

## 规则版本与可解释性

- 调整任何阈值：在 `rules.py` 修改参数并提升对应 `rule_version` 与
  `RULESET_VERSION`，不改动已发布版本；
- 每条告警冻结产生它的规则版本和参数快照，规则升级后历史告警仍可按旧版本回放解释；
- 引擎只读取事件文件，不修改 `data/events.jsonl` 的六字段格式。
