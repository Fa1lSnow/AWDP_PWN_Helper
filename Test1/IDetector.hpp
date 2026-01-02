#pragma once

#include <ida.hpp>
#include <hexrays.hpp>
#include <vector>
#include "VulnData.hpp"

/**
 * 接口类：漏洞检测器
 * 所有具体的漏洞检测器都应继承自该类并实现相应的方法
 */
class IVulnDetector
{
public:

	// 虚析构
	virtual ~IVulnDetector()
	{
	}

	/**
	 * 获取探测器名称
	 */
	virtual const char* getName() const = 0;

	/**
	 * 把反编译好的函数树传入，进行漏洞检测
	 * @param cfunc Hex_Rays 反编译之后的 C 函数对象（AST 根节点）
	 * @param result 结果容器
	 */
	virtual void RunAnalysis(cfunc_t* cfunc, VulnList& result) = 0;
};