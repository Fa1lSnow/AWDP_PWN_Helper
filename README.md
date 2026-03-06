# PwnHelper

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![IDA Pro](https://img.shields.io/badge/IDA%20Pro-9.2+-purple.svg)](https://hex-rays.com/ida-pro/)
[![Platform](https://img.shields.io/badge/platform-Windows-lightgrey.svg)]()
[![Standard](https://img.shields.io/badge/C%2B%2B-17-blue.svg)]()

`PwnHelper` 是面向 **IDA Pro 9.2+** 的二进制漏洞检测与修复辅助插件。  
它基于 Hex-Rays 反编译 AST 做静态规则分析，输出统一漏洞结果，并支持人工确认后的手动 patch 流程。

## 架构

- `IDetector`: 检测器统一接口，所有规则模块都按相同入口运行。
- `ScannerEngine`: 聚合所有 detector，对函数批量扫描并去重汇总。
- `VulnEntry / VulnList`: 漏洞结构体与结果容器，包含类型、风险、修复建议和 patch 元数据。
- `PatchEngine`: 按 `PatchAction` 执行修复（就地参数修补、trampoline 修补、_start 通防修补等）。

## 检测能力

### 1) 栈相关漏洞
- 危险调用审计：`strcpy` / `memcpy` / `read` / `recv` / `snprintf` 等。
- 缓冲区大小追踪：基于栈变量类型信息计算可用容量。
- 边界类问题：`off-by-one` 与 `off-by-null`（含 `buf[idx]=0` 与字节输入后终止符写入模式）。

### 2) 格式化字符串
- 检测 `printf` / `sprintf` / `fprintf` / `snprintf` / `syslog` 等格式化族。
- 对可写段来源、非常量格式串等高风险场景给出高优先级告警。

### 3) 堆/悬垂/整数链路
- `double free` 检测。
- `Dangling Pointer` 检测（free 后未清空、后续仍可达或继续使用）。
- 支持静态槽位与动态索引槽位（如 `notes[idx]`）的可修补场景识别。
- 分配长度表达式审计（`malloc/calloc/realloc` 的潜在整数溢出链路）。

### 4) 危险 API 与命令注入
- 非字面量命令参数调用（`system` / `popen` / `exec*`）。
- 常见高风险 API 使用点审计（如 `strcat/sprintf/scanf`）。

## Patch 机制

- 结果面板包含 `Patch Suggestion` 列。
- 默认流程：**双击仅跳转定位**，人工确认后使用右键 `One Click Patch`（在部分 SDK UI 中显示为 `Edit`）执行修复。
- 当前 patch 动作包含：
  - 参数钳制类修复（将长度参数修补为缓冲区上限，优先就地修补）。
  - 格式串 trampoline 修补（重写参数路径后返回）。
  - 悬垂指针 trampoline 修补（`free -> 清零槽位 -> 返回`，支持动态索引重算）。
  - `_start` 通防修补（手动触发）：在 `__libc_start_main` 前注入 `prctl` + seccomp-bpf 规则。

### Trampoline 落点约束

- 所有 trampoline patch 仅使用 frame 系列段：`.frame.hdr` / `.frame` / `.eh_frame_hdr` / `.eh_frame`。
- 不会回退到其它代码段写入，避免破坏业务代码段布局。

### _start 通防说明

- 扫描结果会默认附加一条 `Generic Defense` 项，地址指向 `_start`（找不到则尝试 `start`）。
- 该项不会自动执行；需要人工在结果列表中右键触发 patch。
- 当前规则重点限制 `execve` 与 `open`，并保留启动路径可继续执行。

## 构建

### 环境要求
- IDA Pro 9.2 SDK
- Visual Studio 2022（Windows）

### 说明
- 工程位于 `Test1/`，入口文件为 `Test1/main.cpp`。
- 插件依赖 Hex-Rays 反编译器，初始化阶段会检查 `init_hexrays_plugin()`。

