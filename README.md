# sqldiag - 基于eBPF的透明MySQL慢查询诊断工具

sqldiag 是一个基于 eBPF (Extended Berkeley Packet Filter) 技术的 MySQL 慢查询诊断 CLI 工具。它通过 uprobe 动态挂载 MySQL 进程的 `dispatch_command` 函数，无需修改 MySQL 代码，无需开启慢查询日志，即可实现对所有 SQL 语句的零开销监控。

## ✨ 功能特性

- **零侵入监控**：不修改 MySQL 代码，不开启慢查询日志，对业务无影响
- **实时捕获**：捕获所有 SQL 语句，包括 COM_QUERY、COM_STMT_PREPARE、COM_STMT_EXECUTE
- **精确计时**：从 query 开始到返回结果的精确耗时统计（纳秒级精度）
- **慢查询告警**：实时打印超过阈值的慢查询到终端
- **多维度聚合**：按用户、数据库、客户端 IP 进行聚合统计
- **JSON 报告**：生成详细的 JSON 格式分析报告
- **表格展示**：友好的控制台表格输出

## 🚀 快速开始

### 系统要求

- Linux Kernel >= 5.8 (支持 BPF CO-RE)
- Root 权限 (CAP_BPF, CAP_PERFMON, CAP_SYS_ADMIN)
- Clang/LLVM >= 14.0 (编译 eBPF 代码)
- Go >= 1.21

### 依赖安装 (Ubuntu/Debian)

```bash
sudo apt-get update
sudo apt-get install -y clang llvm libbpf-dev linux-headers-$(uname -r)
sudo apt-get install -y golang-go
```

### 编译安装

```bash
# 克隆项目
git clone <repository-url>
cd sqldiag

# 编译（自动生成eBPF绑定）
make build

# 安装到系统
sudo make install
```

### 验证安装

```bash
sqldiag --help
```

## 📖 使用说明

### 1. 实时监控慢查询

监控端口 3306 上的 MySQL，阈值 200ms：

```bash
sudo sqldiag mysql -p 3306 --threshold 200
```

按 PID 监控指定 MySQL 进程，持续 5 分钟：

```bash
sudo sqldiag mysql --pid 12345 --duration 5m
```

输出 JSON 格式：

```bash
sudo sqldiag mysql -p 3306 --json
```

### 2. 生成分析报告

收集 1 小时的数据并生成 JSON 报告：

```bash
sudo sqldiag report --since 1h -p 3306 -o report.json
```

收集 30 分钟数据，阈值 100ms：

```bash
sudo sqldiag report --since 30m --threshold 100 -p 3306
```

### 命令行参数

#### 全局参数

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `--threshold` | float | 100.0 | 慢查询阈值（毫秒） |
| `--json` | bool | false | 以 JSON 格式输出 |

#### mysql 子命令

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `-p, --port` | int | 3306 | MySQL 监听端口 |
| `--pid` | int | 0 | MySQL 进程 ID（可选，优先于端口自动检测） |
| `--duration` | duration | 0 | 监控持续时间（如 1h, 30m），0 表示持续运行 |

#### report 子命令

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `--since` | string | "1h" | 报告时间范围（如 1h, 30m, 2h30m） |
| `-o, --output` | string | "" | 输出文件路径（默认输出到标准输出） |
| `-p, --port` | int | 3306 | MySQL 监听端口 |
| `--pid` | int | 0 | MySQL 进程 ID |

## 🔧 技术原理

### 架构设计

```
┌─────────────────────────────────────────────────────────────┐
│                     User Space (Go)                         │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────┐  │
│  │  CLI (cobra)│───▶│  Collector  │───▶│  Aggregator     │  │
│  └─────────────┘    └─────────────┘    └─────────────────┘  │
│                             │                               │
│                             ▼                               │
│                        ┌─────────┐     ┌───────────────┐   │
│                        │ RingBuf │────▶│  Formatter    │   │
│                        └─────────┘     └───────────────┘   │
└─────────────────────────────┬───────────────────────────────┘
                              │
┌─────────────────────────────┼───────────────────────────────┐
│                     Kernel Space (eBPF)                     │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  uprobe: dispatch_command_entry                       │  │
│  │  - 记录开始时间                                        │  │
│  │  - 读取 SQL 语句                                       │  │
│  │  - 提取用户/数据库/客户端信息                          │  │
│  │  - 存入 start_map (Hash Map)                          │  │
│  └───────────────────────┬───────────────────────────────┘  │
│                          │                                  │
│  ┌───────────────────────▼───────────────────────────────┐  │
│  │  uretprobe: dispatch_command_exit                     │  │
│  │  - 从 start_map 读取开始信息                           │  │
│  │  - 计算耗时 (end_ns - start_ns)                       │  │
│  │  - 发送事件到 RingBuf                                 │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### eBPF Hook 点

sqldiag 挂载 MySQL 的 `dispatch_command` 函数，该函数是 MySQL 处理所有客户端命令的入口点：

```c
bool dispatch_command(THD *thd, enum enum_server_command command,
                      char *packet, uint packet_length);
```

- **uprobe**（函数入口）：记录开始时间、SQL 语句、用户、数据库、客户端 IP
- **uretprobe**（函数返回）：计算执行耗时，将完整事件发送到用户空间

### 支持的 MySQL 版本

理论上支持所有开启了调试符号的 MySQL 版本，包括：

- MySQL 5.7.x
- MySQL 8.0.x
- Percona Server
- MariaDB

> **注意**：需要 MySQL 二进制文件保留符号表（未 strip）。如果符号被 stripped，可以通过 `_Z16dispatch_commandP3THDjPcj` (C++ mangled name) 查找。

## 📊 输出示例

### 实时监控输出

```
Attaching to MySQL on port 3306...
Monitoring MySQL slow queries...
Threshold: 200ms
Press Ctrl+C to stop

  Queries: 1523 | Slow: 42 (threshold: 200ms)
2026-06-08 10:23:45.123 [SLOW QUERY] 345.67ms
  Command: COM_QUERY
  User:    app_user
  DB:      ecommerce
  Client:  192.168.1.100:54321
  SQL:     SELECT * FROM orders WHERE status = 'pending' AND created_at < ...
```

### 聚合统计表格

```
  By User
  ----------------------------------------------------------------------------
|        Key        | Count | Total(ms) | Avg(ms) | P95(ms) | Max(ms) | Min(ms) |
|-------------------|-------|-----------|---------|---------|---------|---------|
| app_user          |  1200 |  45234.56 |   37.69 |  156.78 |  523.41 |    0.12 |
| analytics_user    |   323 |  89765.43 |  277.91 |  823.45 | 2341.56 |   12.34 |
|-------------------|-------|-----------|---------|---------|---------|---------|
```

### JSON 报告

```json
{
  "generated_at": "2026-06-08T10:30:00Z",
  "since": "2026-06-08T09:30:00Z",
  "total_queries": 1523,
  "slow_queries": 42,
  "threshold_ms": 200,
  "by_user": {
    "app_user": {
      "count": 1200,
      "total_duration_ms": 45234.56,
      "avg_duration_ms": 37.69,
      "p95_duration_ms": 156.78,
      "max_duration_ms": 523.41,
      "min_duration_ms": 0.12
    }
  },
  "top_slow_queries": [
    {
      "timestamp": "2026-06-08T10:23:45.123Z",
      "duration_ms": 345.67,
      "sql": "SELECT * FROM orders ...",
      "user": "app_user",
      "db": "ecommerce"
    }
  ]
}
```

## 🛡️ 安全说明

- sqldiag 需要 root 权限才能加载 eBPF 程序和挂载 uprobe
- 捕获的 SQL 语句可能包含敏感信息，请妥善处理
- 建议仅在授权的测试和生产环境中使用
- 工具本身不会将任何数据发送到外部网络

## 🔍 性能影响

由于使用 eBPF 技术，sqldiag 的性能开销非常低：

- CPU 使用率增加 < 1%
- 内存占用 < 50MB（主要用于 Ring Buffer）
- 对查询延迟的影响 < 1ms

## 🐛 故障排除

### 错误："eBPF object file not found"

需要在 Linux 环境下编译 eBPF 代码：

```bash
make generate
```

### 错误："no mysql process listening on port 3306"

确认 MySQL 正在运行，或者使用 `--pid` 参数指定进程 ID。

### 错误："symbol dispatch_command not found"

MySQL 二进制文件可能被 stripped 了。尝试安装带调试符号的 MySQL 版本，或者指定 mysqld 的完整路径。

### 错误："operation not permitted"

需要使用 root 权限运行：

```bash
sudo sqldiag mysql -p 3306
```

## 📁 项目结构

```
sqldiag/
├── cmd/sqldiag/
│   ├── main.go          # 程序入口
│   ├── root.go          # 根命令定义
│   ├── mysql.go         # mysql 子命令
│   └── report.go        # report 子命令
├── internal/
│   ├── ebpf/
│   │   ├── mysql.bpf.c  # eBPF C 代码
│   │   ├── mysql_bpf.go # Go 绑定代码
│   │   └── generate.go  # 代码生成指令
│   ├── collector/
│   │   └── collector.go # eBPF 事件收集器
│   ├── aggregator/
│   │   └── aggregator.go# 数据聚合器
│   ├── report/
│   │   └── formatter.go # 报告格式化器
│   └── model/
│       └── event.go     # 数据模型定义
├── Makefile
├── go.mod
├── go.sum
└── README.md
```

## 📄 License

MIT License

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！
