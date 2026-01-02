#pragma once
#include <ida.hpp>
#include <vector>
#include <string>

enum class RiskLevel
{
	INFO,
	LOW,
	MEDIUM,
	HIGH,
	CRITICAL
};

struct VulnEntry
{
	ea_t address;			// 地址
	qstring type;			// 类型
	qstring description;	// 描述
	RiskLevel risk;   // 风险

	VulnEntry() : address(0), risk(RiskLevel::INFO)
	{}

	VulnEntry(ea_t addr, const char* t, const char* desc, RiskLevel r = RiskLevel::HIGH)
		: address(addr), type(t), description(desc), risk(r)
	{}
};

using VulnList = std::vector<VulnEntry>;