#pragma once

#include <ida.hpp>
#include <hexrays.hpp>
#include <vector>
#include "VulnData.hpp"

/**
 * 漏洞检测器接口
 * 所有具体检测器都应继承该类并实现统一分析入口
 */
class IVulnDetector
{
public:

	// 虚析构，保证基类指针释放子类对象安全
	virtual ~IVulnDetector()
	{
	}

	/**
	 * 获取检测器名称
	 */
	virtual const char* getName() const = 0;

	/**
	 * 分析单个函数并向结果集中追加漏洞项
	 * @param cfunc Hex-Rays 反编译得到的函数 AST 根
	 * @param result 漏洞结果容器
	 */
	virtual void RunAnalysis(cfunc_t* cfunc, VulnList& result) = 0;
};
