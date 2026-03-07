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

enum class PatchAction
{
	NONE,
	NOP_CALL,
	CLAMP_SIZE_ARG,
	FRAME_FMT_SAFE_CALL,
	FRAME_FREE_AND_CLEAR_SLOT,
	START_PRCTL_HARDEN
};

struct VulnEntry
{
	ea_t address;			// 漏洞位置地址
	qstring type;			// 漏洞类型
	qstring description;	// 漏洞描述
	RiskLevel risk;			// 风险等级
	qstring patch_suggestion;
	PatchAction patch_action;
	uint64 patch_value;
	int patch_aux;          // Patch 动作的附加参数（如目标参数下标）

	VulnEntry() : address(0), risk(RiskLevel::INFO), patch_action(PatchAction::NONE), patch_value(0), patch_aux(0)
	{}

	VulnEntry(ea_t addr, const char* t, const char* desc, RiskLevel r = RiskLevel::HIGH)
		: address(addr), type(t), description(desc), risk(r), patch_action(PatchAction::NONE), patch_value(0), patch_aux(0)
	{}

	VulnEntry(ea_t addr, const char* t, const char* desc, RiskLevel r, const char* suggestion, PatchAction action)
		: address(addr), type(t), description(desc), risk(r), patch_suggestion(suggestion), patch_action(action), patch_value(0), patch_aux(0)
	{}

	VulnEntry(ea_t addr, const char* t, const char* desc, RiskLevel r, const char* suggestion, PatchAction action, uint64 value, int aux)
		: address(addr), type(t), description(desc), risk(r), patch_suggestion(suggestion), patch_action(action), patch_value(value), patch_aux(aux)
	{}
};

using VulnList = std::vector<VulnEntry>;
