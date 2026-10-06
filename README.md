# cluster-posture-scan-go

集群配置安全基线的本地扫描工具。集群对象以快照形式从本地目录读入，
按版本化基线评估，输出逐字节稳定的结论报表，支持增量复核、豁免管理与断点恢复。

## 构建与测试

```sh
go build ./...
go test ./...
```

## 快速开始

```sh
# 扫描（--state 启用增量复核与断点恢复）
cpscan scan --snapshot ./snap --baseline ./baseline.yaml --version v1 \
    --state ./state.json --exemptions ./exemptions.json --out report.json

# 登记 / 撤销 / 查看豁免
cpscan exempt register --exemptions exemptions.json --audit audit.log \
    --actor sec-admin --id e1 --check no-privileged \
    --kind Pod --namespace prod --name web \
    --reason "legacy workload" --expires 2027-01-01T00:00:00Z
cpscan exempt revoke --exemptions exemptions.json --audit audit.log --actor sec-admin --id e1
cpscan exempt list --exemptions exemptions.json
```

## 快照模型与合并规则

- 快照目录下所有 `.yaml` / `.yml` / `.json` 文件都会被读入；YAML 支持
  多文档（`---` 分隔），JSON 支持单对象或对象数组。
- 每份文档必须是 Kubernetes 风格对象：含 `kind`、`metadata.name`，
  可选 `metadata.namespace`。
- 对象以 `(Kind, Namespace, Name)` 为唯一键。同一键出现多份文档时，
  按 **(文件相对路径, 文件内文档序号) 字典序** 排序，字典序最小者优先级最高：
  - 字段级深合并：map 递归合并；
  - 标量冲突时高优先级文档胜出；
  - 低优先级文档仅补充高优先级文档中缺失的键。
- 文件解析可并发进行，但合并只在排序后的序列上做，因此解析结果与
  读入顺序、并发度无关，逐条一致。

## 基线模型

基线文件（YAML/JSON）可包含多个版本，只有显式选择版本才会改变结论：

```yaml
versions:
  - version: v1
    checks:
      - id: no-privileged          # 检查 ID，版本内唯一
        severity: high             # critical | high | medium | low
        kinds: [Pod]               # 适用对象种类，* 表示全部
        condition:
          path: spec.privileged    # 点分字段路径
          op: eq                   # 判定操作
          value: true
        message: privileged pod detected
  - version: v2
    checks: [...]
```

每条结论都记录求值所用的 `baselineVersion`：基线升级到 v2 后，
v1 对历史快照的结论仍然可复现、可解释；只有显式 `--version v2`
才会改变结论（版本切换会使增量缓存失效并全量重估）。

### 判定操作

条件成立即判定为**违规（fail）**，否则通过（pass）。

| op | 语义 | 备注 |
|---|---|---|
| `eq` | 字段等于 value | 数值按规范化比较 |
| `ne` | 字段不等于 value | **字段缺失也算违规**（用于 require- 类检查） |
| `exists` / `not-exists` | 字段存在 / 不存在 | 不需要 value |
| `in` | 字段在 value 列表中 | value 为数组 |
| `contains` | 列表包含 value，或字符串包含子串 | |
| `regex` | 字段匹配正则 | value 为正则字符串 |
| `lt` / `lte` / `gt` / `gte` | 数值比较 | |

## 扫描与结论

- 引擎对 (检查 × 适用对象) 并发求值，结论统一按 `(CheckID, 对象键)`
  排序，严重度汇总确定性输出，与调度顺序、机器并发度无关。
- 豁免不作为求值输入，而是求值后的纯函数后处理（fail → exempt），
  因此缓存的增量结论在豁免变化时依然安全可复用。

## 增量复核与断点恢复

`--state` 指定的状态文件同时承担两个职责：

- **增量复核**：每个对象以其规范化内容指纹（SHA-256）缓存结论。
  重扫时只对指纹变化的对象重新求值；快照中消失的对象不进入新状态，
  其旧结论随之回收。增量结论与全量重扫逐条一致。
- **断点恢复**：状态按对象粒度原子提交（临时文件 + rename），
  `--commit-every N` 控制每求值 N 个对象提交一次。中断后重新执行
  同一命令即可从最近已提交位置继续；已完成的评估不会重复执行，
  未完成的部分不会留下半成品结论，继续后的结果与一次性跑完相同。

## 豁免模型

```json
{
  "approvers": ["sec-admin"],
  "exemptions": [
    {"id": "e1", "checkId": "no-privileged",
     "ref": {"kind": "Pod", "namespace": "prod", "name": "web"},
     "reason": "legacy workload", "createdBy": "sec-admin",
     "expiresAt": "2027-01-01T00:00:00Z"}
  ]
}
```

- 豁免绑定到具体 `(检查, 对象)`，必须带到期时间。
- 过期或已撤销的豁免不再压制结论。
- 只有 `approvers` 中登记的主体可以登记/撤销；越权操作被拒绝并
  追加到审计日志（JSONL，含时间、操作者、动作、决定与原因），
  所有登记与撤销均可复核。

## 报表

报表为 JSON，包含 `baselineVersion`、按严重度分级的 `summary`
（critical/high/medium/low 仅统计 fail，pass/exempt 单独计数）与
有序 `findings`。报表不含时间戳等易变字段，同一快照在同一基线
版本下输出逐字节稳定，可直接纳入自动化校验（如 `cmp` 比对）。

## 配置项一览（cpscan scan）

| 参数 | 说明 | 默认 |
|---|---|---|
| `--snapshot` | 快照目录（必填） | |
| `--baseline` | 基线文件（必填） | |
| `--version` | 基线版本 | 文件中第一个版本 |
| `--state` | 状态文件，启用增量与断点恢复 | 关闭（纯全量） |
| `--exemptions` | 豁免文件 | 无豁免 |
| `--out` | 报表输出路径 | 标准输出 |
| `--concurrency` | 求值并发度 | NumCPU |
| `--commit-every` | 每 N 个对象提交一次状态 | 仅结束时提交 |

## 测试覆盖

- `internal/snapshot`：对象冲突合并、多文档优先级、并发/顺序无关性；
- `internal/baseline`：版本演进、未知版本报错、全部判定操作语义；
- `internal/engine`：多并发度多次运行结论逐条一致、排序确定性；
- `internal/scan`：增量与全量一致、消失对象结论回收、断点恢复、
  版本切换缓存失效、端到端豁免到期与报表字节稳定性；
- `internal/exemption`：越权登记/撤销拒绝与审计留痕、到期过滤、持久化；
- `internal/report`：渲染逐字节稳定、汇总正确性、空结论输出。
