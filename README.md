# PwnHelper

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![IDA Pro](https://img.shields.io/badge/IDA%20Pro-9.2+-purple.svg)](https://hex-rays.com/ida-pro/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey.svg)]()
[![Standard](https://img.shields.io/badge/C%2B%2B-17-blue.svg)]()

**PwnHelper** 是一个专为 **IDA Pro 9.2+** 设计的现代化漏洞挖掘辅助插件。它基于 Hex-Rays SDK 构建，采用模块化架构设计，旨在通过静态数据流分析自动识别二进制程序中的高危漏洞。

## 🏗️ 架构设计 (Architecture)

本项目采用 **Allman 代码风格**，基于 C++ 接口设计的可扩展架构：
* **`IDetector`**: 核心抽象基类，所有检测器均继承于此。
* **`VulnList`**: 统一的漏洞结果容器，支持风险分级与去重。
* **插件入口**: 自动遍历所有已注册的 Detector 并聚合分析结果。

## ✨ 功能特性 (Features)

### 1. 栈溢出检测 (Stack Buffer Overflow)
* 针对 `strcpy`, `strcat`, `memcpy`, `read` 等危险函数进行参数审计。
* **缓冲区大小追踪**: 静态计算栈变量 (`cot_var`) 的分配大小。
* **溢出判定**: 对比源数据长度（如常量字符串或已知大小的内存）与目标缓冲区大小，自动标记确定性的溢出路径。

### 2. 格式化字符串漏洞检测 (Format String)
* 支持 `printf`, `sprintf`, `syslog` 等格式化输出函数族。

* **智能误报过滤 (Smart Filtering)**: 
  
  * 通过检测内存段权限 (`SEGPERM_WRITE`)，自动将被编译器放入 `.rodata` (只读段) 的全局字符串视为安全，**误报率低**。
  
* **风险分级**:
  * `Critical`: 格式化串来自栈变量。
  * `High`: 格式化串来自可写全局段 (.data/.bss)。
  * `High`: 格式化串来自函数返回值或未知指针。
  
  ### 3. ...

## 🛠️ 构建 (Build)

### 环境要求
* IDA Pro 9.2 SDK 
* Visual Studio 2022 (Windows) / GCC 11+ (Linux)

