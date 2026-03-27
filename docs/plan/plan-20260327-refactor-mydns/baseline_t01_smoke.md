# T01 Smoke Baseline (plan-20260327-refactor-mydns)

- task_id: T01
- generated_at: 2026-03-27
- source: 复用上轮 smoke 结果（未重复大规模执行）

## 两轮 smoke 汇总

执行范围（T01 约定）：
- `tests/test_config.py`
- `tests/test_pipeline_step2.py`
- `tests/test_resolver_manager_step3.py`
- `tests/test_selector_step4.py`
- `tests/test_https_record_hook.py`

汇总：
- Round 1: **56/56 passed**
- Round 2: **56/56 passed**
- Combined: **112/112 passed**

## Hook 顺序关键用例通过列表

以下关键顺序约束用例在两轮 smoke 中均通过：

- ✅ `tests/test_config.py::test_domain_rule_hook_should_load_after_cache_when_declared_manually`
- ✅ `tests/test_config.py::test_tagset_hook_should_load_when_declared_manually`
- ✅ `tests/test_config.py::test_tagset_hook_after_speedcheck_should_raise`
- ✅ `tests/test_config.py::test_ip_rule_hook_should_load_after_tagset_and_before_speedcheck`
- ✅ `tests/test_config.py::test_ip_rule_hook_after_speedcheck_should_raise`
- ✅ `tests/test_config.py::test_ip_rule_hook_before_tagset_should_raise`

## 关键时延样本（step3/性能相关）

说明：本次补录不重跑大套件；以下为 smoke 套件中的关键时延门禁样本（断言阈值），可用于后续重构前后对照。

- `tests/test_resolver_manager_step3.py::test_concurrent_collect` → `duration < 0.20s`
- `tests/test_resolver_manager_step3.py::test_timeout_and_tag_filter` → `duration < 0.20s`
- `tests/test_resolver_manager_step3.py::test_resolver_specific_timeout_should_override_global_timeout` → `duration < 0.15s`
- `tests/test_resolver_manager_step3.py`（提前返回相关用例）→ `duration < 0.18s`
- `tests/test_resolver_manager_step3.py`（提前返回相关用例）→ `duration < 0.13s`
- `tests/test_speedcheck_hooks.py::test_probe_timeout_should_not_break_request` → `duration < 0.12s`

## Flaky 判定

- 结论：**当前未观察到 flaky**
- 依据：同一 smoke 集合连续两轮均为 56/56 通过，未出现轮次间不一致。
