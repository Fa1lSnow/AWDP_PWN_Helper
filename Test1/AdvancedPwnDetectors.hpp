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
	// 释放状态跟踪：按局部变量、全局对象、表达式键三种粒度并行记录
	// 这样可以覆盖 var/obj/idx/ref 等不同 AST 形态，降低漏报
	std::unordered_set<int> m_freed_vars;
	std::unordered_set<ea_t> m_freed_objs;
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
		m_freed_vars.clear();
		m_freed_objs.clear();
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

		ReportDanglingPointerUse(expr, func_name);
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

	bool ExtractVarOrObj(cexpr_t* expr, int& var_idx, ea_t& obj_ea) const
	{
		cexpr_t* real = SkipCasts(expr);
		if (real == nullptr)
		{
			return false;
		}

		if (real->op == cot_ref && real->x != nullptr)
		{
			real = SkipCasts(real->x);
		}

		if (real == nullptr)
		{
			return false;
		}

		if (real->op == cot_var)
		{
			var_idx = real->v.idx;
			return true;
		}

		if (real->op == cot_obj)
		{
			obj_ea = real->obj_ea;
			return true;
		}

		return false;
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
				detail.cat_sprnt("Potential dangling-pointer: freed target '%s' remains globally reachable and is not reset before function exit (slot=%a).", key.c_str(), slot_ea);
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
				detail.cat_sprnt("Potential dangling-pointer: freed target '%s' remains globally reachable and is not reset before function exit.", key.c_str());
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

	bool IsFreedTargetAlias(const std::string& key) const
	{
		if (key.empty())
		{
			return false;
		}

		for (const auto& cur : m_freed_targets)
		{
			if (cur == key || cur.find(key) != std::string::npos || key.find(cur) != std::string::npos)
			{
				return true;
			}
		}

		return false;
	}

	void ClearFreedState(cexpr_t* lhs)
	{
		// 一旦发生写入，相关“已释放”状态应失效，
		// 否则会把重新赋值后的指针误判为悬垂使用
		int var_idx = -1;
		ea_t obj_ea = BADADDR;
		bool has_var_or_obj = ExtractVarOrObj(lhs, var_idx, obj_ea);

		if (has_var_or_obj && var_idx >= 0)
		{
			m_freed_vars.erase(var_idx);
		}
		if (has_var_or_obj && obj_ea != BADADDR)
		{
			m_freed_objs.erase(obj_ea);
		}

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

		int var_idx = -1;
		ea_t obj_ea = BADADDR;
		bool has_var_or_obj = ExtractVarOrObj(target_expr, var_idx, obj_ea);
		if (!has_var_or_obj && target_key.empty())
		{
			return;
		}

		bool already_freed = false;
		if (var_idx >= 0)
		{
			already_freed = (m_freed_vars.find(var_idx) != m_freed_vars.end());
		}
		else if (obj_ea != BADADDR)
		{
			already_freed = (m_freed_objs.find(obj_ea) != m_freed_objs.end());
		}
		if (!already_freed && !target_key.empty())
		{
			already_freed = (m_freed_targets.find(target_key) != m_freed_targets.end());
		}

		if (already_freed)
		{
			m_results->emplace_back(call->ea,
				"Double Free",
				"Potential double free: same pointer appears to be freed multiple times in one function path.",
				RiskLevel::CRITICAL,
				"Patch: add NULLing/reassignment after free and ensure ownership transfer checks before deallocation.",
				PatchAction::NOP_CALL);
		}

		if (var_idx >= 0)
		{
			m_freed_vars.insert(var_idx);
		}
		if (obj_ea != BADADDR)
		{
			m_freed_objs.insert(obj_ea);
		}
		if (!target_key.empty())
		{
			m_freed_targets.insert(target_key);
			TrackDanglingCandidate(target_key, target_expr, call->ea);
		}
	}

	void GatherFreedRefs(cexpr_t* expr, bool& found, int depth = 0) const
	{
		// 大深度保护，避免在恶意或退化 AST 上递归失控
		if (expr == nullptr || found || depth > 128)
		{
			return;
		}

		cexpr_t* real = SkipCasts(expr);
		if (real == nullptr)
		{
			return;
		}

		if (real->op == cot_var)
		{
			std::string key = BuildExprKey(real);
			if (!key.empty() && m_freed_targets.find(key) != m_freed_targets.end())
			{
				found = true;
				return;
			}

			if (m_freed_vars.find(real->v.idx) != m_freed_vars.end())
			{
				found = true;
			}
			return;
		}

		if (real->op == cot_obj)
		{
			std::string key = BuildExprKey(real);
			if (!key.empty() && m_freed_targets.find(key) != m_freed_targets.end())
			{
				found = true;
				return;
			}

			if (m_freed_objs.find(real->obj_ea) != m_freed_objs.end())
			{
				found = true;
			}
			return;
		}

		std::string expr_key = BuildExprKey(real);
		if (!expr_key.empty() && m_freed_targets.find(expr_key) != m_freed_targets.end())
		{
			found = true;
			return;
		}

		if (real->op == cot_ref && real->x != nullptr)
		{
			GatherFreedRefs(real->x, found, depth + 1);
			return;
		}

		if (real->op == cot_idx && real->x != nullptr)
		{
			GatherFreedRefs(real->x, found, depth + 1);
			return;
		}

		if (real->op == cot_call && real->a != nullptr)
		{
			for (size_t i = 0; i < real->a->size(); ++i)
			{
				GatherFreedRefs(&(*real->a)[i], found, depth + 1);
				if (found)
				{
					return;
				}
			}
		}
	}

	void ReportDanglingPointerUse(cexpr_t* call, const std::string& func_name)
	{
		if (m_results == nullptr || call->a == nullptr)
		{
			return;
		}

		for (size_t i = 0; i < call->a->size(); ++i)
		{
			cexpr_t* arg = SkipCasts(&(*call->a)[i]);
			if (arg == nullptr)
			{
				continue;
			}

			bool found_freed = false;

			std::string arg_key = BuildExprKey(arg);
			if (!arg_key.empty() && IsFreedTargetAlias(arg_key))
			{
				found_freed = true;
			}
			else if (arg->op == cot_var && m_freed_vars.find(arg->v.idx) != m_freed_vars.end())
			{
				found_freed = true;
			}
			else if (arg->op == cot_obj && m_freed_objs.find(arg->obj_ea) != m_freed_objs.end())
			{
				found_freed = true;
			}

			if (found_freed)
			{
				qstring detail;
				detail.cat_sprnt("Potential dangling-pointer use: argument %llu in call '%s' references memory freed earlier in this function.",
					static_cast<unsigned long long>(i),
					func_name.c_str());
				m_results->emplace_back(call->ea,
					"Dangling Pointer",
					detail.c_str(),
					RiskLevel::CRITICAL,
					"Patch: mark .eh_frame_hdr/.eh_frame executable, trampoline, clear arg0 pointer before safe continuation.",
					PatchAction::FRAME_CLEAR_ARG0_CALL);
				return;
			}
		}
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

	bool IsOverflowProneSizeExpr(cexpr_t* expr, int depth = 0) const
	{
		// 仅将“非常量算术”视为可疑；纯常量表达式默认认为编译期已固定
		if (depth > 128)
		{
			return false;
		}

		cexpr_t* real = SkipCasts(expr);
		if (real == nullptr)
		{
			return false;
		}

		if (real->op == cot_mul || real->op == cot_add || real->op == cot_shl)
		{
			if (!IsConstExpr(real, depth + 1))
			{
				return true;
			}

			return IsOverflowProneSizeExpr(real->x, depth + 1) || IsOverflowProneSizeExpr(real->y, depth + 1);
		}

		return false;
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
			if (IsOverflowProneSizeExpr(size_expr))
			{
				m_results->emplace_back(call->ea,
					"Integer Overflow to Heap Overflow",
					"Allocator size expression uses non-constant arithmetic that may wrap/truncate before allocation.",
					RiskLevel::HIGH,
					"Patch: add overflow guards before allocation (e.g., if (n != 0 && size > SIZE_MAX / n) fail).",
					PatchAction::NONE);
			}
		}

		if (func_name == "realloc" && call->a->size() >= 2)
		{
			cexpr_t* size_expr = &(*call->a)[1];
			if (IsOverflowProneSizeExpr(size_expr))
			{
				m_results->emplace_back(call->ea,
					"Integer Overflow to Heap Overflow",
					"realloc size expression appears overflow-prone (arithmetic on variable terms).",
					RiskLevel::HIGH,
					"Patch: validate computed size with checked arithmetic before realloc.",
					PatchAction::NONE);
			}
		}

		if (func_name == "calloc" && call->a->size() >= 2)
		{
			cexpr_t* n_expr = &(*call->a)[0];
			cexpr_t* sz_expr = &(*call->a)[1];
			if (!IsConstExpr(n_expr) || !IsConstExpr(sz_expr))
			{
				m_results->emplace_back(call->ea,
					"Integer Overflow to Heap Overflow",
					"calloc(count, size) uses non-constant terms; count * size may overflow.",
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
