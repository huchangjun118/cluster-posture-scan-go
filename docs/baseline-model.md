# 基线模型与判定语义

本文档定义扫描器的对象归一、基线版本、字段判定、增量复核、豁免与恢复语义。
所有规则都是显式且可复现的，不依赖文件读入顺序、调度顺序或机器并发度。

## 1. 对象归一与合并

### 1.1 对象身份

对象以三元组 `(Kind, Namespace, Name)` 唯一标识：

- `Kind` 来自 `kind`；
- `Name` 来自 `metadata.name`（必填）；
- `Namespace` 来自 `metadata.namespace`（集群级资源为空）。

### 1.2 读入流程

1. 递归遍历快照目录，收集所有 `*.json`/`*.jsonl`，按路径**字典序**排序。
2. 以固定 worker 池并发解析；每个文件的解析结果是有序的。
3. 收集结果后进入**单线程顺序合并阶段**。因此无论 worker 数或调度如何抖动，
   归一结果完全一致。

### 1.3 重复对象合并规则

同一身份出现多份拷贝时：

1. 比较 `metadata.resourceVersion`（按无符号整数比较；缺失按 `0`）。
2. **版本号高者胜**。
3. 版本号相同按**来源路径字典序较小者胜**（保证无随机平局）。

胜出拷贝整体成为该对象的内容（不做字段级混合，避免产生任何输入中都不存在的
状态）。每次合并都会产生 `MergeReport`：

- `sources`：所有拷贝（来源、版本、规范化内容 ID），按来源排序；
- `conflicts`：所有“叶子字段”取值不一致的路径，记录每个来源的原始值与最终
  采用值，按字段路径排序。`metadata.resourceVersion` 的差异本身不作为冲突。

### 1.4 对象指纹

指纹 = 对规范化内容（kind/namespace/name/labels/spec/metadata，键排序、
**排除 resourceVersion**）计算 SHA-256。它用于：

- 变化检测（增量复核只重评指纹变化对象）；
- 快照 ID：对 `(对象身份, 指纹)` 排序后再次哈希，得到整份快照的稳定 ID。

## 2. 版本化基线

### 2.1 不可变性

`Registry` 中发布过的 `(Version, Checks)` 不可修改：

- 以相同内容重复注册同一版本 → 幂等成功；
- 以不同内容重复注册 → 拒绝。

状态文件按**基线版本**分文件（`review-<version>.json`），切换基线不会改写其他
版本的历史复核结论。

### 2.2 内置版本

| 检查 | 含义 | v1 | v2 |
| --- | --- | --- | --- |
| `C-001:<Workload>` | 容器不得 `privileged: true` | high | high |
| `C-002:<Workload>` | Pod 不得共享主机网络 `hostNetwork` | high | high |
| `C-003:<Workload>` | 每个容器必须声明 CPU requests | **medium** | **high（收紧）** |
| `C-004` | Namespace 必须带 `owner` 标签 | 无 | medium（新增） |
| `C-005` | Service 不得使用 NodePort | medium | medium |
| `C-006` | ServiceAccount 不得默认自动挂载 API token | low | low |

工作负载检查按 Kind 复制为 `C-00x:Pod`、`C-00x:Deployment`、`C-00x:Job` 等，
适用 Kind：Pod、Deployment、StatefulSet、DaemonSet、Job、CronJob。

“只有显式切换基线版本才会改变结论”：不指定 `--baseline` 时取**最新**版本；
要复现历史结论必须显式传旧版本号。

### 2.3 字段选择器

- `labels.<key>`
- `metadata.<dotted.path>`
- `spec.<dotted.path>`
- `container:<容器内字段路径>`：对每个（init）容器求值，例如
  `container:securityContext.privileged`；命中容器名进入结论消息。
- `resource:<requests|limits>.<cpu|memory>[.<容器名>]`：对每个容器求值；
  指定容器名时只针对该容器，容器不存在则条件不成立。

### 2.4 判定算子

一条检查包含若干条件，**全部成立（AND）时对象判为不合规**。

| 算子 | 含义 |
| --- | --- |
| `eq` / `ne` | 字段存在且等于/不等于期望值 |
| `exists` / `missing` | 字段存在 / 缺失 |
| `lt` `lte` `gt` `gte` | 数值比较（资源数量支持 `m/k/K/M/G/Ki/Mi/Gi` 等量纲后缀） |
| `matches` | 字符串匹配正则 |

`container:` 与 `resource:` 伪字段在**至少一个**适用容器上成立时，整条条件
成立（例如内置 `C-003` 使用 `resource:requests.cpu` + `missing`，表示“存在
缺少 CPU requests 的容器”）；被命中的容器名会附加到结论消息中。

## 3. 评估单元与确定性

- 评估单元 = 一条适用检查 × 一个对象；单元 ID = `checkID|Kind/Namespace/Name`。
- 工作计划按“检查 ID 升序 → 对象 Key 升序”做全序枚举。
- 单元并发求值，结果按单元回收；最终结论统一按
  **严重度（critical>high>medium>low）→ 检查 ID → Kind → Namespace → Name**
  排序。
- 汇总按固定严重度/状态桶输出（零值桶也保留），因此 JSON 形状恒定。
- 评估时刻由 `--as-of` 固定（或取引擎时钟），同一快照同一基线同一时刻下
  JSON 报表逐字节相同。

## 4. 增量复核状态

每个基线版本一个状态文件：

```json
{
  "baseline": "1",
  "snapshot_id": "<上次快照ID>",
  "unit_fp": {"<unit>": "<对象指纹>"},
  "unit_ex": {"<unit>": "<生效豁免ID签名>"},
  "findings": [ ...已提交结论... ]
}
```

增量判定（对当前快照的每个适用单元）：

| 情况 | 处理 |
| --- | --- |
| 单元已不存在（对象删除/Kind 不再适用） | 丢弃结论，计入 `revoked`（回收） |
| 对象指纹未变 且 豁免签名未变 | 复用上一次结论，不重评 |
| 对象指纹变化，或豁免签名变化 | 丢弃旧结论，重新评估 |

豁免签名 = 当前生效豁免 ID 排序后逗号连接（无生效豁免为空串）。因此豁免**授予、
到期、撤销**即使在对象完全未变时也会触发相关单元重评，保证“过期豁免不再压制
结论”，且增量结果与全量重扫一致。

全量扫描遇到不同快照 ID 时从头重建该版本的复核流；同一快照的全量扫描则承担
“断点续跑”职责（见第 5 节）。

## 5. 中断与恢复

- 每个评估单元**完整求值后**才进入提交流；未完成单元不会留下任何半成品结论。
- 提交采用“同目录临时文件 + fsync + rename”原子替换。
- `--commit-every N` 控制提交频率（默认每单元一次）。
- 续跑时只信任状态中已提交的单元与其结论；其余单元重新执行，所以已完成评估
  不会重复执行。
- 续跑完成后结果与一次性跑完相同（有测试 `TestInterruptionRecoveryEqualsOneShot`
  覆盖）。

## 6. 豁免模型

- 豁免**绑定**到具体检查与对象：`(CheckID, Kind, Namespace, Name)`，不会影响
  其他检查/对象。
- 生效窗口 `[CreatedAt, ExpiresAt)`，可撤销；到期点之后立即失效。
- 豁免 ID 由绑定关系与窗口确定性派生，重复登记幂等。
- 仅授权 actor 可授予/撤销（默认 `admin`，可用 `exemption.WithAdmins` 配置）。
  越权操作返回 `PermissionError`，且无论成功失败都写入**只增**审计记录
  （actor/动作/目标/是否拒绝/原因）。
- 存储同样使用原子写，拒绝动作不会产生任何豁免数据。

## 7. 配置项汇总

库内主要配置：

- `object.NewLoader(dir, concurrency)`：快照根目录与解析并发度。
- `scan.Config{Workers, StateDir, BaselineVer, AsOf, CommitEvery}`。
- `scan.WithClock(fn)` / `scan.WithFailureInjection(n)`：时钟注入与中断测试钩子。
- `exemption.WithClock(fn)` / `exemption.WithAdmins(actors...)`。

CLI 配置项见根 `README.md` 的命令与配置项表。
