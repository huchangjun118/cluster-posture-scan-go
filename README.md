# cluster-posture-scan

本地集群配置安全基线扫描器。集群对象以**快照文件**形式从本地目录读入，扫描器
对快照运行**版本化基线**，产出确定性的安全结论，并支持增量复核、豁免管理与中断
恢复。

- 纯 Go 标准库实现，无外部依赖。
- 同一份快照 + 同一基线版本 + 同一评估时刻，报表**逐字节稳定**，可直接纳入
  自动化校验。

## 快速开始

```bash
# 列出已发布基线
go run ./cmd/scanner versions

# 查看快照归一结果（对象合并/冲突）
go run ./cmd/scanner inspect --snapshot ./testdata/snap

# 全量扫描（基线默认最新版；可用 --baseline 显式指定）
go run ./cmd/scanner scan --snapshot ./testdata/snap --baseline 1 --as-of 2026-01-01T00:00:00Z

# 增量复核（只重评变化对象，回收已消失对象的旧结论）
go run ./cmd/scanner scan --snapshot ./testdata/snap --incremental --baseline 1

# 登记 / 撤销 / 查看豁免
go run ./cmd/scanner exempt grant  --check C-001:Pod --kind Pod --namespace ns --name p \
    --expires 2026-02-01T00:00:00Z --reason breakglass --actor admin
go run ./cmd/scanner exempt revoke --id EX-xxxx --actor admin
go run ./cmd/scanner exempt list
```

## 命令与配置项

| 选项 | 适用命令 | 说明 |
| --- | --- | --- |
| `--snapshot DIR` | scan/inspect | 本地快照目录，递归读取 `*.json` 与 `*.jsonl` |
| `--baseline VER` | scan | 显式指定基线版本；缺省取最新已发布版本。**只有显式切换版本，历史快照的结论才会改变** |
| `--incremental` | scan | 增量复核模式 |
| `--workers N` | scan/inspect | 解析/评估并发度（默认 4）。结果与并发度无关 |
| `--state DIR` | 全部 | 复核断点与豁免存储目录（默认 `./.scan-state`） |
| `--format F` | scan | `json`（默认，字节稳定）或 `text` |
| `--as-of RFC3339` | scan | 固定评估时刻（豁免到期判定、结论时间戳）。固定后输出完全可复现 |
| `--commit-every N` | scan | 每完成 N 个评估单元提交一次断点（默认 1） |
| `--actor A` | exempt | 操作者身份；非授权操作者被拒绝并审计 |

退出码：`0` 成功；`1` 一般错误；`2` 用法错误；`3` 扫描被中断（进度已提交，
重跑同一命令即从断点继续）。

## 快照格式

- `*.json`：单个对象，或对象数组。
- `*.jsonl`：每行一个对象，空行允许。

对象至少需要 `kind` 与 `metadata.name`；支持 `metadata.namespace`、
`metadata.labels`、`spec`。数字按 `json.Number` 精确解析，不经过浮点。

```json
{
  "kind": "Pod",
  "metadata": {"name": "web", "namespace": "prod", "resourceVersion": "3"},
  "spec": {"hostNetwork": true, "containers": [{"name": "app",
    "securityContext": {"privileged": true}}]}
}
```

## 目录结构

```
internal/object    快照加载、确定性解析与重复对象合并
internal/baseline  版本化基线、字段判定条件、内置基线 v1/v2
internal/finding   结论模型、确定性排序与严重度汇总
internal/exemption 豁免登记/到期/撤销、授权与审计
internal/scan      全量/增量/并发评估、断点恢复
internal/report    字节稳定报表
cmd/scanner        CLI
```

## 关键一致性保证

1. **读入确定性**：文件按路径排序后并发解析，结果按固定顺序合并；合并规则
   显式（见 `docs/baseline-model.md`），与读入顺序、并发度无关。
2. **基线不可变**：已发布基线不可修改；历史结论始终可在其基线版本下复现。
3. **增量等价**：增量复核结论与同快照全量重扫**逐条一致**；消失对象的结论被
   回收并在 `revoked` 中列出。
4. **并发确定**：评估单元（检查 × 对象）并发求值，结论按“严重度 → 检查 ID →
   对象”全序排序。
5. **中断恢复**：仅提交完整评估完的单元；续跑不重复执行、不留半成品结论。
6. **豁免到期**：豁免签名（生效豁免 ID 集合）随单元一起记录；即使对象未变，
   豁免授予/到期/撤销也会触发该单元重新评估。

详细的基线模型、算子与合并/复核语义见 [docs/baseline-model.md](docs/baseline-model.md)。

## 测试

```bash
go test ./...
go test -race ./internal/...
```

覆盖：对象冲突合并、基线版本演进、增量/全量一致、并发确定性、豁免到期与
越权审计、中断恢复、报表字节稳定。
