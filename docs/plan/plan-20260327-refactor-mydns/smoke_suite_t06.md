# T06 Minimal Smoke Suite（先烟测后全量）

- task_id: T06
- date: 2026-03-27
- scope: 最小回归门禁（hook 顺序、上游策略、HTTPS、speedcheck）

## 最小烟测集合

### 推荐一条命令执行

`uv run python -m unittest -v tests.test_config tests.test_resolver_manager_step3 tests.test_https_record_hook tests.test_speedcheck_hooks tests.test_speedcheck_utils`

### 覆盖模块（最小集）

- `tests.test_config`：hook 顺序约束（DomainRule/Cache、TagSet/IPRule/SpeedCheck）
- `tests.test_resolver_manager_step3`：上游策略（A/AAAA = wait_all；non-A/HTTPS = first_success）
- `tests.test_https_record_hook`：HTTPS 记录改写、ECH、子查询去重路径
- `tests.test_speedcheck_hooks`：测速 Hook 主链行为
- `tests.test_speedcheck_utils`：测速工具函数与边界语义

## 先烟测后全量流程

1. 先运行上面的最小烟测命令。
2. 若烟测失败：立即停止，不进入全量；按下表做波次/T 任务定位。
3. 若烟测通过：再执行全量回归：
   - `uv run python -m unittest discover -s tests -v`
4. 全量失败时：按失败模块回溯到对应波次/T 任务，优先回看最近改动。

## 失败定位映射（失败模块 -> 对应波次/T任务）

| 失败模块 | 主要定位波次 | 对应 T 任务 | 说明 |
|---|---|---|---|
| `tests.test_config` | Wave 1 | T02 | 配置装配链与 hook 顺序语义 |
| `tests.test_resolver_manager_step3` | Wave 3 | T04 | ResolverManager 收集策略与并发提前返回 |
| `tests.test_https_record_hook` | Wave 3 / 4 | T05 / T06 | HTTPS 多 rdata、ECH、子查询去重与回归补测 |
| `tests.test_speedcheck_hooks` | Wave 2 / 3 | T03 / T05 | speedcheck hook 行为与抽取后语义一致性 |
| `tests.test_speedcheck_utils` | Wave 3 | T05 | speedcheck 工具函数与性能路径语义 |

## 备注

- 本文件用于 T06 快速门禁，不替代 T07 的最终全量验收。
- 执行顺序固定：**先烟测，后全量**。
