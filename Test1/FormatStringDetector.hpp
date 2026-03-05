#pragma once

#include <hexrays.hpp>
#include <unordered_map>
#include <segment.hpp>
#include <string>

#include "IDetector.hpp"

#ifdef _DEBUG
#define LOG_DEBUG(...) msg(__VA_ARGS__)
#else
#define LOG_DEBUG(...)
#endif

class FormatStringDetector : public IVulnDetector, public ctree_visitor_t
{
private:
	// ���溯������Ӧ�ĸ�ʽ���ַ����Ĳ�������
	using FormatFuncMap = std::unordered_map<std::string, int>;
	FormatFuncMap m_func_map;

	VulnList* m_results;

public:
	FormatStringDetector() : ctree_visitor_t(CV_FAST)
	{
		// printf(fmt, ...) -> idx 0
		RegisterFunc("printf", 0);
		RegisterFunc("vprintf", 0);
		RegisterFunc("dprintf", 1);
		RegisterFunc("vfprintf", 1);

		// sprintf(buf, fmt, ...) -> idx 1
		RegisterFunc("sprintf", 1);
		RegisterFunc("fprintf", 1);
		RegisterFunc("syslog", 1);
		RegisterFunc("vsyslog", 1);
		RegisterFunc("__printf_chk", 1);
		RegisterFunc("__fprintf_chk", 2);
		RegisterFunc("__sprintf_chk", 3);
		RegisterFunc("__snprintf_chk", 4);

		// snprintf(buf, len, fmt, ...) -> idx 2
		RegisterFunc("snprintf", 2);
		RegisterFunc("vsnprintf", 2);
	}

	virtual const char* getName() const override
	{
		return "Format String Vulnerability Detector";
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

	// ����ע��
	void RegisterFunc(const std::string& name, int fmt_idx)
	{
		m_func_map[name] = fmt_idx;
		if (!name.empty() && name[0] != '.' && name[0] != '_')
		{
			m_func_map["." + name] = fmt_idx;
			m_func_map["_" + name] = fmt_idx;
		}
	}

	// ���� cast ����ת��
	cexpr_t* SkipCasts(cexpr_t* expr)
	{
		cexpr_t* cur = expr;
		while (cur != nullptr && cur->op == cot_cast)
		{
			cur = cur->x;
		}
		return cur;
	}

	virtual int idaapi visit_expr(cexpr_t* expr) override
	{
		if (expr == nullptr || expr->op != cot_call || expr->x == nullptr)
		{
			return 0;
		}

		// ��ȡ������
		qstring func_name_q;
		if (expr->x->op == cot_obj)
		{
			get_func_name(&func_name_q, expr->x->obj_ea);
		}
		else if (expr->x->op == cot_helper)
		{
			func_name_q = expr->x->helper;
		}
		else
		{
			return 0;
		}

		std::string name = func_name_q.c_str();
		std::string lookup_name = name;
		if (!lookup_name.empty() && (lookup_name[0] == '.' || lookup_name[0] == '_'))
		{
			lookup_name.erase(0, 1);
		}

		auto it = m_func_map.find(name);
		if (it == m_func_map.end())
		{
			it = m_func_map.find(lookup_name);
		}
		if (it != m_func_map.end())
		{
			int fmt_idx = it->second;
			CheckFormatString(expr, fmt_idx, name);
		}

		return 0;
	}
	
private:
	
	void CheckFormatString(cexpr_t* call, int fmt_idx, const std::string& func_name)
	{
		if (m_results == nullptr || call == nullptr || call->a == nullptr || fmt_idx < 0)
		{
			return;
		}

		// �����������
		if (call->a->size() <= fmt_idx)
		{
			return;
		}

		// ��ȡ��ʽ�ַ�������
		cexpr_t* fmt_arg = &(*call->a)[fmt_idx];

		// ���� cast
		cexpr_t* real_fmt = SkipCasts(fmt_arg);
		if (real_fmt == nullptr)
		{
			return;
		}

		if (real_fmt->op != cot_str)
		{
			RiskLevel risk = RiskLevel::HIGH;
			qstring info;

			//�ֲ�����
			if (real_fmt->op == cot_var)
			{
				info.cat_sprnt("Risk: Local Var (Stack) used in '%s'", func_name.c_str());
				risk = RiskLevel::CRITICAL;
			}
			// ȫ�ֱ������ڴ����
			else if (real_fmt->op == cot_obj)
			{
				segment_t* seg = getseg(real_fmt->obj_ea);

				if (seg != nullptr)
				{
					if (!((seg->perm) & SEGPERM_WRITE))
					{
						return;
					}
				}
				qstring gname;
				get_name(&gname, real_fmt->obj_ea);
				info.cat_sprnt("Risk: Global Var '%s' used in '%s'", gname.c_str(), func_name.c_str());
				risk = RiskLevel::CRITICAL;
			}
			// ���á�ָ��
			else if (real_fmt->op == cot_ref)
			{
				info.cat_sprnt("Risk: Pointer/Reference used in '%s'", func_name.c_str());
				risk = RiskLevel::CRITICAL;
			}
			// ��������ֵ
			else if (real_fmt->op == cot_call)
			{
				info.cat_sprnt("Risk: Function Return Value used in '%s'", func_name.c_str());
			}
			else
			{
				info.cat_sprnt("Format String: Non-literal argument used in '%s' (Op: %d)", func_name.c_str(), real_fmt->op);
			}

			m_results->emplace_back(call->ea, "Format String Vulnerability", info.c_str(), risk);

			LOG_DEBUG("[FmtDetector] Found vuln at %a: %s\n", call->ea, info.c_str());
		}
	}
	
};
