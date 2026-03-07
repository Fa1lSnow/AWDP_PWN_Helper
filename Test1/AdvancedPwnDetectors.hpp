#pragma once

#include <hexrays.hpp>
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <cstdlib>

#include "IDetector.hpp"

class HeapAndIntegerDetector : public IVulnDetector, public ctree_visitor_t
{
private:
	struct PendingDanglingInfo
	{
		ea_t call_ea;
		ea_t slot_ea;

		PendingDanglingInfo() : call_ea(BADADDR), slot_ea(BADADDR)
		{
		}

		PendingDanglingInfo(ea_t c, ea_t s) : call_ea(c), slot_ea(s)
		{
		}
	};

	VulnList* m_results;
	cfunc_t* m_cfunc;
	std::unordered_set<std::string> m_freed_targets;
	// 延迟上报：函数扫描完后再输出“未清空悬垂指针”结果，
	// 避免中间路径被后续赋值修正时提前误报
	std::unordered_map<std::string, PendingDanglingInfo> m_pending_dangling;

public:
	HeapAndIntegerDetector() : ctree_visitor_t(CV_FAST), m_results(nullptr), m_cfunc(nullptr)
	{
	}

	virtual const char* getName() const override
	{
		return "Heap/Dangling/Integer Detector";
	}

	virtual void RunAnalysis(cfunc_t* cfunc, VulnList& result) override
	{
		if (cfunc == nullptr)
		{
			return;
		}

		m_results = &result;
		m_cfunc = cfunc;
		m_freed_targets.clear();
		m_pending_dangling.clear();
		this->apply_to(&cfunc->body, nullptr);
		EmitPendingDangling();
	}

protected:
	virtual int idaapi visit_expr(cexpr_t* expr) override
	{
		if (expr == nullptr)
		{
			return 0;
		}

		if (expr->op == cot_asg && expr->x != nullptr)
		{
			ClearFreedState(expr->x);
		}

		if (expr->op != cot_call || expr->x == nullptr)
		{
			return 0;
		}

		std::string func_name;
		if (!GetCallName(expr, func_name))
		{
			return 0;
		}

		if (IsFreeLike(func_name) && IsTrustedFreeCall(expr, func_name))
		{
			HandleFreeCall(expr);
			return 0;
		}

		CheckAllocatorIntegerRisk(expr, func_name);

		return 0;
	}

private:
	static cexpr_t* SkipCasts(cexpr_t* expr)
	{
		cexpr_t* cur = expr;
		while (cur != nullptr && cur->op == cot_cast)
		{
			cur = cur->x;
		}
		return cur;
	}

	bool GetCallName(cexpr_t* call, std::string& out_name) const
	{
		qstring func_name_q;
		if (call->x->op == cot_obj)
		{
			get_func_name(&func_name_q, call->x->obj_ea);
		}
		else if (call->x->op == cot_helper)
		{
			func_name_q = call->x->helper;
		}
		else
		{
			return false;
		}

		out_name = func_name_q.c_str();
		if (!out_name.empty() && (out_name[0] == '.' || out_name[0] == '_'))
		{
			out_name.erase(0, 1);
		}
		return !out_name.empty();
	}

	static bool IsFreeLike(const std::string& name)
	{
		return name == "free" || name == "cfree" || name == "operator delete";
	}

	bool IsTrustedFreeCall(cexpr_t* call, const std::string& name) const
	{
		if (!IsFreeLike(name) || call == nullptr || call->x == nullptr)
		{
			return false;
		}

		if (call->x->op == cot_helper)
		{
			qstring helper = call->x->helper;
			if (helper.empty())
			{
				return false;
			}

			std::string raw = helper.c_str();
			if (raw.rfind("__imp_", 0) == 0 || raw.rfind("imp_", 0) == 0)
			{
				return true;
			}

			return false;
		}

		if (call->x->op != cot_obj)
		{
			return false;
		}

		ea_t callee_ea = call->x->obj_ea;
		func_t* callee_func = get_func(callee_ea);
		if (callee_func != nullptr && (callee_func->flags & (FUNC_LIB | FUNC_THUNK)))
		{
			return true;
		}

		segment_t* seg = getseg(callee_ea);
		if (seg == nullptr)
		{
			return false;
		}

		if (seg->type == SEG_XTRN)
		{
			return true;
		}

		qstring seg_name;
		get_segm_name(&seg_name, seg);
		return seg_name == ".plt" || seg_name == ".plt.got" || seg_name == ".plt.sec" || seg_name == ".idata" || seg_name == ".extern";
	}

	static bool IsAllocator(const std::string& name)
	{
		return name == "malloc" || name == "calloc" || name == "realloc" || name == "operator new";
	}

	enum class SizeExprRisk
	{
		NONE,
		LOW,
		HIGH
	};

	static SizeExprRisk MergeRisk(SizeExprRisk a, SizeExprRisk b)
	{
		return static_cast<int>(a) > static_cast<int>(b) ? a : b;
	}

	std::string BuildExprKey(cexpr_t* expr, int depth = 0) const
	{
		// 递归深度限制用于防止异常 AST 触发指数级展开
		if (expr == nullptr || depth > 24)
		{
			return std::string();
		}

		cexpr_t* real = SkipCasts(expr);
		if (real == nullptr)
		{
			return std::string();
		}

		if (real->op == cot_var)
		{
			return std::string("var:") + std::to_string(real->v.idx);
		}

		if (real->op == cot_obj)
		{
			return std::string("obj:") + std::to_string(static_cast<unsigned long long>(real->obj_ea));
		}

		if (real->op == cot_num)
		{
			return std::string("num:") + std::to_string(static_cast<unsigned long long>(real->n->_value));
		}

		if (real->op == cot_ref && real->x != nullptr)
		{
			std::string xk = BuildExprKey(real->x, depth + 1);
			if (!xk.empty())
			{
				return std::string("ref(") + xk + ")";
			}
			return std::string();
		}

		if (real->op == cot_ptr && real->x != nullptr)
		{
			std::string xk = BuildExprKey(real->x, depth + 1);
			if (!xk.empty())
			{
				return std::string("ptr(") + xk + ")";
			}
			return std::string();
		}

		if (real->op == cot_idx && real->x != nullptr)
		{
			std::string base = BuildExprKey(real->x, depth + 1);
			std::string idx;
			if (real->y != nullptr)
			{
				idx = BuildExprKey(real->y, depth + 1);
			}
			if (!base.empty())
			{
				if (idx.empty())
				{
					idx = "?";
				}
				return base + "[" + idx + "]";
			}
			return std::string();
		}

		if ((real->op == cot_add || real->op == cot_sub) && real->x != nullptr && real->y != nullptr)
		{
			std::string lk = BuildExprKey(real->x, depth + 1);
			std::string rk = BuildExprKey(real->y, depth + 1);
			if (!lk.empty() && !rk.empty())
			{
				return lk + (real->op == cot_add ? "+" : "-") + rk;
			}
		}

		return std::string();
	}

	void ClearFreedTargetsByAlias(const std::string& base_key)
	{
		// 使用双向子串匹配做“别名近似消解”
		// 这是启发式策略：更偏向减少漏报，可能引入少量保守清理
		if (base_key.empty())
		{
			return;
		}

		for (auto it = m_freed_targets.begin(); it != m_freed_targets.end();)
		{
			const std::string& cur = *it;
			if (cur == base_key || cur.find(base_key) != std::string::npos || base_key.find(cur) != std::string::npos)
			{
				it = m_freed_targets.erase(it);
			}
			else
			{
				++it;
			}
		}
	}

	void ClearPendingDanglingByAlias(const std::string& base_key)
	{
		if (base_key.empty())
		{
			return;
		}

		for (auto it = m_pending_dangling.begin(); it != m_pending_dangling.end();)
		{
			const std::string& cur = it->first;
			if (cur == base_key || cur.find(base_key) != std::string::npos || base_key.find(cur) != std::string::npos)
			{
				it = m_pending_dangling.erase(it);
			}
			else
			{
				++it;
			}
		}
	}

	static bool IsGlobalReachableKey(const std::string& key)
	{
		return key.find("obj:") != std::string::npos;
	}

	static bool TryParseObjBaseFromKey(const std::string& key, ea_t& out_base)
	{
		out_base = BADADDR;
		size_t p = key.find("obj:");
		if (p == std::string::npos)
		{
			return false;
		}

		p += 4;
		size_t e = p;
		while (e < key.size() && key[e] >= '0' && key[e] <= '9')
		{
			++e;
		}
		if (e == p)
		{
			return false;
		}

		std::string num = key.substr(p, e - p);
		out_base = static_cast<ea_t>(::strtoull(num.c_str(), nullptr, 10));
		return out_base != BADADDR;
	}

	bool TryResolveConstAddrExpr(cexpr_t* expr, ea_t& out_ea) const
	{
		cexpr_t* real = SkipCasts(expr);
		if (real == nullptr)
		{
			return false;
		}

		if (real->op == cot_obj)
		{
			out_ea = real->obj_ea;
			return true;
		}

		if (real->op == cot_num)
		{
			out_ea = static_cast<ea_t>(real->n->_value);
			return true;
		}

		if ((real->op == cot_add || real->op == cot_sub) && real->x != nullptr && real->y != nullptr)
		{
			ea_t l = BADADDR;
			ea_t r = BADADDR;
			if (TryResolveConstAddrExpr(real->x, l) && TryResolveConstAddrExpr(real->y, r))
			{
				out_ea = (real->op == cot_add) ? (l + r) : (l - r);
				return true;
			}
		}

		return false;
	}

	bool TryResolveStorageSlotEA(cexpr_t* freed_arg_expr, ea_t& out_slot_ea) const
	{
		out_slot_ea = BADADDR;
		cexpr_t* real = SkipCasts(freed_arg_expr);
		if (real == nullptr)
		{
			return false;
		}

		if (real->op == cot_obj)
		{
			out_slot_ea = real->obj_ea;
			return true;
		}

		if (real->op == cot_ptr && real->x != nullptr)
		{
			return TryResolveConstAddrExpr(real->x, out_slot_ea);
		}

		return false;
	}

	void TrackDanglingCandidate(const std::string& key, cexpr_t* target_expr, ea_t call_ea)
	{
		if (key.empty() || !IsGlobalReachableKey(key))
		{
			return;
		}

		ea_t slot_ea = BADADDR;
		TryResolveStorageSlotEA(target_expr, slot_ea);

		if (m_pending_dangling.find(key) == m_pending_dangling.end())
		{
			m_pending_dangling[key] = PendingDanglingInfo(call_ea, slot_ea);
		}
	}

	void EmitPendingDangling()
	{
		if (m_results == nullptr)
		{
			return;
		}

		// 扫描结束后统一输出：此时更能确认“free 后仍全局可达且未置空”
		for (const auto& kv : m_pending_dangling)
		{
			const std::string& key = kv.first;
			ea_t ea = kv.second.call_ea;
			ea_t slot_ea = kv.second.slot_ea;

			qstring detail;
			if (slot_ea != BADADDR)
			{
				detail.cat_sprnt("Dangling pointer risk: freed target '%s' remains globally reachable and is not reset to NULL before function exit (slot=%a).", key.c_str(), slot_ea);
				m_results->emplace_back(ea,
					"Dangling Pointer",
					detail.c_str(),
					RiskLevel::CRITICAL,
					"Patch: jmp to .eh_frame trampoline, call free, then clear resolved slot address to NULL.",
					PatchAction::FRAME_FREE_AND_CLEAR_SLOT,
					static_cast<uint64>(slot_ea),
					0);
			}
			else
			{
				detail.cat_sprnt("Dangling pointer risk: freed target '%s' remains globally reachable and is not reset to NULL before function exit.", key.c_str());
				ea_t dyn_base = BADADDR;
				if (TryParseObjBaseFromKey(key, dyn_base))
				{
					m_results->emplace_back(ea,
						"Dangling Pointer",
						detail.c_str(),
						RiskLevel::CRITICAL,
						"Patch: jmp to .eh_frame trampoline, call free, recompute notes[idx]-style slot, then clear slot to NULL.",
						PatchAction::FRAME_FREE_AND_CLEAR_SLOT,
						static_cast<uint64>(dyn_base),
						1);
					continue;
				}

				m_results->emplace_back(ea,
					"Dangling Pointer",
					detail.c_str(),
					RiskLevel::CRITICAL,
					"Patch: unresolved dynamic slot address. Manually add slot NULLing right after free.",
					PatchAction::NONE);
			}
		}
	}

	void ClearFreedState(cexpr_t* lhs)
	{
		// 一旦发生写入，相关“已释放”状态应失效，
		// 否则会把重新赋值后的指针误判为悬垂使用
		std::string key = BuildExprKey(lhs);
		if (!key.empty())
		{
			ClearFreedTargetsByAlias(key);
			ClearPendingDanglingByAlias(key);
		}
	}

	void HandleFreeCall(cexpr_t* call)
	{
		if (m_results == nullptr || call->a == nullptr || call->a->empty())
		{
			return;
		}

		cexpr_t* target_expr = &(*call->a)[0];
		std::string target_key = BuildExprKey(target_expr);
		if (target_key.empty())
		{
			return;
		}

		m_freed_targets.insert(target_key);
		TrackDanglingCandidate(target_key, target_expr, call->ea);
	}

	bool IsConstExpr(cexpr_t* expr, int depth = 0) const
	{
		if (depth > 128)
		{
			return false;
		}

		cexpr_t* real = SkipCasts(expr);
		if (real == nullptr)
		{
			return false;
		}

		if (real->op == cot_num || real->op == cot_str)
		{
			return true;
		}

		if (real->op == cot_add || real->op == cot_sub || real->op == cot_mul || real->op == cot_shl)
		{
			return IsConstExpr(real->x, depth + 1) && IsConstExpr(real->y, depth + 1);
		}

		return false;
	}

	SizeExprRisk EvaluateSizeExprRisk(cexpr_t* expr, int depth = 0) const
	{
		if (depth > 128)
		{
			return SizeExprRisk::LOW;
		}

		cexpr_t* real = SkipCasts(expr);
		if (real == nullptr)
		{
			return SizeExprRisk::NONE;
		}

		if (real->op == cot_num)
		{
			return SizeExprRisk::NONE;
		}

		if (real->op == cot_var || real->op == cot_obj)
		{
			return SizeExprRisk::LOW;
		}

		if ((real->op == cot_add || real->op == cot_sub) && real->x != nullptr && real->y != nullptr)
		{
			SizeExprRisk lhs = EvaluateSizeExprRisk(real->x, depth + 1);
			SizeExprRisk rhs = EvaluateSizeExprRisk(real->y, depth + 1);
			SizeExprRisk merged = MergeRisk(lhs, rhs);
			if (lhs != SizeExprRisk::NONE && rhs != SizeExprRisk::NONE)
			{
				return MergeRisk(SizeExprRisk::LOW, merged);
			}
			return merged;
		}

		if (real->op == cot_mul && real->x != nullptr && real->y != nullptr)
		{
			cexpr_t* x = SkipCasts(real->x);
			cexpr_t* y = SkipCasts(real->y);
			if (x == nullptr || y == nullptr)
			{
				return SizeExprRisk::LOW;
			}

			if (x->op == cot_num && y->op == cot_num)
			{
				return SizeExprRisk::NONE;
			}

			if (x->op == cot_num || y->op == cot_num)
			{
				cexpr_t* c = (x->op == cot_num) ? x : y;
				const uint64 k = c->n->_value;
				return (k <= 4) ? SizeExprRisk::LOW : SizeExprRisk::HIGH;
			}

			return SizeExprRisk::HIGH;
		}

		if (real->op == cot_shl && real->x != nullptr && real->y != nullptr)
		{
			cexpr_t* shift = SkipCasts(real->y);
			if (shift != nullptr && shift->op == cot_num)
			{
				const uint64 bits = shift->n->_value;
				return (bits <= 2) ? SizeExprRisk::LOW : SizeExprRisk::HIGH;
			}
			return SizeExprRisk::HIGH;
		}

		if (real->x != nullptr || real->y != nullptr)
		{
			SizeExprRisk lhs = real->x != nullptr ? EvaluateSizeExprRisk(real->x, depth + 1) : SizeExprRisk::NONE;
			SizeExprRisk rhs = real->y != nullptr ? EvaluateSizeExprRisk(real->y, depth + 1) : SizeExprRisk::NONE;
			return MergeRisk(lhs, rhs);
		}

		return SizeExprRisk::LOW;
	}

	void CheckAllocatorIntegerRisk(cexpr_t* call, const std::string& func_name)
	{
		if (m_results == nullptr || call->a == nullptr || !IsAllocator(func_name))
		{
			return;
		}

		if ((func_name == "malloc" || func_name == "operator new") && call->a->size() >= 1)
		{
			cexpr_t* size_expr = &(*call->a)[0];
			if (EvaluateSizeExprRisk(size_expr) == SizeExprRisk::HIGH)
			{
				m_results->emplace_back(call->ea,
					"Integer Overflow to Heap Overflow",
					"Allocator size expression contains high-risk arithmetic (multi-variable multiply/large-scale growth) that may wrap before allocation.",
					RiskLevel::HIGH,
					"Patch: add checked arithmetic guard before allocation (e.g., reject on multiplication/shift overflow).",
					PatchAction::NONE);
			}
		}

		if (func_name == "realloc" && call->a->size() >= 2)
		{
			cexpr_t* size_expr = &(*call->a)[1];
			if (EvaluateSizeExprRisk(size_expr) == SizeExprRisk::HIGH)
			{
				m_results->emplace_back(call->ea,
					"Integer Overflow to Heap Overflow",
					"realloc size expression contains high-risk arithmetic (multi-variable multiply/large-scale growth).",
					RiskLevel::HIGH,
					"Patch: validate computed size with checked arithmetic before realloc.",
					PatchAction::NONE);
			}
		}

		if (func_name == "calloc" && call->a->size() >= 2)
		{
			cexpr_t* n_expr = &(*call->a)[0];
			cexpr_t* sz_expr = &(*call->a)[1];
			SizeExprRisk nr = EvaluateSizeExprRisk(n_expr);
			SizeExprRisk sr = EvaluateSizeExprRisk(sz_expr);
			if (nr == SizeExprRisk::HIGH || sr == SizeExprRisk::HIGH)
			{
				m_results->emplace_back(call->ea,
					"Integer Overflow to Heap Overflow",
					"calloc(count, size) uses high-risk size terms; count * size may overflow.",
					RiskLevel::HIGH,
					"Patch: add checked multiplication before calloc and reject overflowed products.",
					PatchAction::NONE);
			}
		}
	}
};

class DangerousCallDetector : public IVulnDetector, public ctree_visitor_t
{
private:
	using IndexMap = std::unordered_map<std::string, int>;
	VulnList* m_results;
	IndexMap m_command_sinks;
	std::unordered_set<std::string> m_dangerous_apis;

public:
	DangerousCallDetector() : ctree_visitor_t(CV_FAST), m_results(nullptr)
	{
		RegisterCommandSink("system", 0);
		RegisterCommandSink("popen", 0);
		RegisterCommandSink("execl", 0);
		RegisterCommandSink("execle", 0);
		RegisterCommandSink("execlp", 0);
		RegisterCommandSink("execv", 0);
		RegisterCommandSink("execvp", 0);

		RegisterDangerousApi("strcat");
		RegisterDangerousApi("strncat");
		RegisterDangerousApi("sprintf");
		RegisterDangerousApi("vsprintf");
		RegisterDangerousApi("scanf");
		RegisterDangerousApi("sscanf");
		RegisterDangerousApi("fscanf");
	}

	virtual const char* getName() const override
	{
		return "Dangerous API / Command Injection Detector";
	}

	virtual void RunAnalysis(cfunc_t* cfunc, VulnList& result) override
	{
		if (cfunc == nullptr)
		{
			return;
		}

		m_results = &result;
		this->apply_to(&cfunc->body, nullptr);
	}

protected:
	virtual int idaapi visit_expr(cexpr_t* expr) override
	{
		if (expr == nullptr || expr->op != cot_call || expr->x == nullptr)
		{
			return 0;
		}

		std::string func_name;
		if (!GetCallName(expr, func_name))
		{
			return 0;
		}

		auto sink_it = m_command_sinks.find(func_name);
		if (sink_it != m_command_sinks.end())
		{
			CheckCommandSink(expr, func_name, sink_it->second);
		}

		if (m_dangerous_apis.find(func_name) != m_dangerous_apis.end())
		{
			ReportDangerousApi(expr, func_name);
		}

		return 0;
	}

private:
	void RegisterCommandSink(const std::string& name, int arg_idx)
	{
		m_command_sinks[name] = arg_idx;
		if (!name.empty())
		{
			m_command_sinks["_" + name] = arg_idx;
			m_command_sinks["." + name] = arg_idx;
		}
	}

	void RegisterDangerousApi(const std::string& name)
	{
		m_dangerous_apis.insert(name);
		if (!name.empty())
		{
			m_dangerous_apis.insert("_" + name);
			m_dangerous_apis.insert("." + name);
		}
	}

	static cexpr_t* SkipCasts(cexpr_t* expr)
	{
		cexpr_t* cur = expr;
		while (cur != nullptr && cur->op == cot_cast)
		{
			cur = cur->x;
		}
		return cur;
	}

	bool GetCallName(cexpr_t* call, std::string& out_name) const
	{
		qstring func_name_q;
		if (call->x->op == cot_obj)
		{
			get_func_name(&func_name_q, call->x->obj_ea);
		}
		else if (call->x->op == cot_helper)
		{
			func_name_q = call->x->helper;
		}
		else
		{
			return false;
		}

		out_name = func_name_q.c_str();
		if (!out_name.empty() && (out_name[0] == '.' || out_name[0] == '_'))
		{
			out_name.erase(0, 1);
		}
		return !out_name.empty();
	}

	void CheckCommandSink(cexpr_t* call, const std::string& func_name, int cmd_idx)
	{
		if (m_results == nullptr || call->a == nullptr || cmd_idx < 0 || call->a->size() <= static_cast<size_t>(cmd_idx))
		{
			return;
		}

		cexpr_t* cmd = SkipCasts(&(*call->a)[cmd_idx]);
		if (cmd == nullptr)
		{
			return;
		}

		if (cmd->op != cot_str)
		{
			qstring detail;
			detail.cat_sprnt("Potential command injection: '%s' command argument is non-literal.", func_name.c_str());
			m_results->emplace_back(call->ea,
				"Command Injection",
				detail.c_str(),
				RiskLevel::CRITICAL,
				"Patch: replace shell invocation with execve-style argument vector and strict allowlist validation.",
				PatchAction::NOP_CALL);
		}
	}

	void ReportDangerousApi(cexpr_t* call, const std::string& func_name)
	{
		if (m_results == nullptr)
		{
			return;
		}

		qstring detail;
		detail.cat_sprnt("Dangerous API usage: '%s' often leads to exploitable memory corruption/input risks.", func_name.c_str());
		m_results->emplace_back(call->ea,
			"Dangerous API",
			detail.c_str(),
			RiskLevel::HIGH,
			"Patch: migrate to bounded alternatives with explicit length checks and input constraints.",
			PatchAction::NOP_CALL);
	}
};
