# T07 最终验收摘要

- task_id: T07
- date: 2026-03-27
- note: 本摘要基于当前分支既有执行记录整理，未重复执行测试。

## 结果总览

- 烟测结果：**69/69 通过**
- 全量结果：**138/138 通过**

## 与 T01 基线对比结论

结论：**无语义退化**。

对照项说明：
- hook 顺序约束（DomainRule/Cache、TagSet/IPRule/SpeedCheck）保持一致；
- 上游策略保持一致（A/AAAA = wait_all；non-A/HTTPS = first_success）；
- HTTPS 记录改写与 speedcheck 相关行为在验收记录中未出现回归。

## 后续若出现回归失败的定位策略

1. 先执行最小烟测集，禁止直接跳全量。
2. 若烟测失败，按失败模块回溯波次：
   - `tests.test_config` → Wave 1 / T02（配置装配与 hook 顺序）
   - `tests.test_resolver_manager_step3` → Wave 3 / T04（上游收集策略）
   - `tests.test_https_record_hook` → Wave 3/4 / T05/T06（HTTPS 多 rdata、ECH、去重）
   - `tests.test_speedcheck_hooks`、`tests.test_speedcheck_utils` → Wave 2/3 / T03/T05（测速路径）
3. 仅对失败模块对应波次做最小回滚或定点修复，再重跑烟测。
4. 烟测恢复后再执行全量回归，最终更新验收记录。