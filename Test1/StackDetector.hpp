#pragma once

#include <hexrays.hpp>
#include <unordered_map>
#include <functional>
#include <string>
#include "IDetector.hpp"

#ifdef _DEBUG
#define LOG_DEBUG(...) msg(__VA_ARGS__)
#else
#define LOG_DEBUG(...)
#endif

class StackDetector : public IVulnDetector, public ctree_visitor_t
{
private:
    using handlerFunc = std::function<void(cexpr_t*)>;

    VulnList* m_results;
    cfunc_t* m_cfunc;
    std::unordered_map<std::string, handlerFunc> m_dispatch_map;

public:
    StackDetector() : ctree_visitor_t(CV_FAST)
    {
        // ע��ص�
        auto check_gets = [this](cexpr_t* e) { CheckGets(e); };
        m_dispatch_map["gets"] = check_gets;
        m_dispatch_map["_gets"] = check_gets;
        m_dispatch_map[".gets"] = check_gets;

        auto check_strcpy = [this](cexpr_t* e) { CheckStrcpy(e); };
        m_dispatch_map["strcpy"] = check_strcpy;
        m_dispatch_map["_strcpy"] = check_strcpy;
        m_dispatch_map[".strcpy"] = check_strcpy;

        auto check_memcpy = [this](cexpr_t* e) { CheckMemcpy(e); };
        m_dispatch_map["memcpy"] = check_memcpy;
        m_dispatch_map["_memcpy"] = check_memcpy;
        m_dispatch_map[".memcpy"] = check_memcpy;

        auto check_read = [this](cexpr_t* e) { CheckRead(e); };
        m_dispatch_map["read"] = check_read;
        m_dispatch_map["_read"] = check_read;
        m_dispatch_map[".read"] = check_read;
    }

    virtual const char* getName() const override
    {
        return "Stack-Based Buffer Overflow Detector";
    }

    virtual void RunAnalysis(cfunc_t* cfunc, VulnList& result) override
    {
        if (cfunc == nullptr)
        {
            return;
        }

        m_results = &result;
        m_cfunc = cfunc;
        this->apply_to(&cfunc->body, nullptr);
    }

protected:
    // ���� cast ����ת�����ҵ����Ľڵ�
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
        if (expr == nullptr || expr->op != cot_call || expr->x == nullptr) return 0;

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

        auto it = m_dispatch_map.find(name);
        if (it != m_dispatch_map.end())
        {
            LOG_DEBUG("[StackDetector] checking call: %s at %a\n", name.c_str(), expr->ea);
            it->second(expr);
        }

        return 0;
    }

private:
    uint64_t GetStackBufferSize(cexpr_t* arg_expr)
    {
        // ���� Cast 
        cexpr_t* real_expr = SkipCasts(arg_expr);
        if (real_expr == nullptr)
        {
            return 0;
        }

        int idx = -1;

        // &buf (cot_ref -> cot_var)
        if (real_expr->op == cot_ref && real_expr->x != nullptr && real_expr->x->op == cot_var)
        {
            idx = real_expr->x->v.idx;
        }
        // buf (cot_var)
        else if (real_expr->op == cot_var)
        {
            idx = real_expr->v.idx;
        }
        // &buf[0] (cot_ref -> cot_idx -> cot_var)
        else if (real_expr->op == cot_ref && real_expr->x != nullptr && real_expr->x->op == cot_idx)
        {
            if (real_expr->x->x != nullptr && real_expr->x->x->op == cot_var)
            {
                idx = real_expr->x->x->v.idx;
            }
        }

        LOG_DEBUG("  [GetSize] Op: %d, Idx: %d\n", real_expr->op, idx);

        if (idx == -1 || m_cfunc == nullptr) return 0;

        lvars_t* lvars_ptr = m_cfunc->get_lvars();
        if (!lvars_ptr || idx < 0 || static_cast<size_t>(idx) >= lvars_ptr->size()) return 0;

        lvar_t* var = &(*lvars_ptr)[idx];
        if (var)
        {
            uint64_t size = 0;
            if (var->type().is_array())
            {
                size = var->type().get_size();
            }
            // Only arrays have a measurable stack buffer size; pointers/scalars yield 0.
            LOG_DEBUG("  [GetSize] Found: %s, Size: %llu\n", var->name.c_str(), static_cast<unsigned long long>(size));
            return size;
        }
        return 0;
    }

    void CheckGets(cexpr_t* call)
    {
        if (m_results == nullptr || call == nullptr || call->a == nullptr || call->a->size() < 1) return;
        m_results->emplace_back(call->ea, "Stack Overflow(Critical)", "Usage of 'gets'", RiskLevel::CRITICAL);
    }

    void CheckStrcpy(cexpr_t* call)
    {
        if (m_results == nullptr || call == nullptr || call->a == nullptr || call->a->size() < 2) return;

        cexpr_t* dest = &(*call->a)[0];
        cexpr_t* src = &(*call->a)[1];

        uint64_t dest_size = GetStackBufferSize(dest);
        cexpr_t* real_src = SkipCasts(src);
        if (real_src == nullptr)
        {
            return;
        }

        if (dest_size > 0)
        {
			// src Ϊ�ַ�������
            if (real_src->op == cot_str)
	        {
		        qstring content;
	        	if (real_src->string) content = real_src->string;
	        	if (content.length() >= dest_size)
	        	{
                    LOG_DEBUG("  [CheckRead] !!! OVERFLOW DETECTED !!!\n");
	        		qstring msg;
	        		msg.cat_sprnt("Strcpy Overflow: len %llu >= buf %llu", static_cast<unsigned long long>(content.length()), static_cast<unsigned long long>(dest_size));
	        		m_results->emplace_back(call->ea, "Stack Overflow(Critical)", msg.c_str(), RiskLevel::CRITICAL);
	        	}
	        }
            // src Ϊ�������ӱ���ʽ���޷�ȷ����С
            else
            {
                LOG_DEBUG("  [CheckRead] !!! POSSIBLE OVERFLOW DETECTED !!!\n");
                qstring msg;
                msg.cat_sprnt("Risky Strcpy: Unknown source len into fixed buf (%llu)", static_cast<unsigned long long>(dest_size));
                m_results->emplace_back(call->ea, "Potential Stack Overflow", msg.c_str(), RiskLevel::HIGH);
			}
        }
    }

    void CheckMemcpy(cexpr_t* call)
    {
        if (m_results == nullptr || call == nullptr || call->a == nullptr || call->a->size() < 3) return;

        cexpr_t* dest = &(*call->a)[0];
        cexpr_t* len = &(*call->a)[2];

        uint64_t dest_size = GetStackBufferSize(dest);
        cexpr_t* real_len = SkipCasts(len);
        if (real_len == nullptr)
        {
            return;
        }

        if (dest_size > 0)
        {
			// len Ϊ������
            if (real_len->op == cot_num)
	        {
		        if (real_len->n->_value > dest_size)
		        {
                    LOG_DEBUG("  [CheckRead] !!! OVERFLOW DETECTED !!!\n");
		        	qstring msg;
		        	msg.cat_sprnt("Memcpy Overflow: Copy %llu > Dst %llu", static_cast<unsigned long long>(real_len->n->_value), static_cast<unsigned long long>(dest_size));
		        	m_results->emplace_back(call->ea, "Stack Overflow", msg.c_str(), RiskLevel::CRITICAL);
		        }
	        }
			// len Ϊ�������ӱ���ʽ���޷�ȷ����С
            else
            {
                LOG_DEBUG("  [CheckRead] !!! POSSIBLE OVERFLOW DETECTED !!!\n");
                qstring msg;
                msg.cat_sprnt("Potential Overflow: Memcpy variable size into fixed buf (%llu)", static_cast<unsigned long long>(dest_size));
                m_results->emplace_back(call->ea, "Variable Size Memcpy", msg.c_str(), RiskLevel::HIGH);
            }
        }
    }

    void CheckRead(cexpr_t* call)
    {
        if (m_results == nullptr || call == nullptr || call->a == nullptr || call->a->size() < 3) return;

        // read(fd, buf, len)
        cexpr_t* dest = &(*call->a)[1];
        cexpr_t* len = &(*call->a)[2];

        uint64_t dest_size = GetStackBufferSize(dest);
        cexpr_t* real_len = SkipCasts(len);
        if (real_len == nullptr)
        {
            return;
        }

        LOG_DEBUG("  [CheckRead] DstSize: %llu, WriteLenOp: %d\n", static_cast<unsigned long long>(dest_size), real_len->op);

        if (dest_size > 0 )
        {
            // len Ϊ������
            if (real_len->op == cot_num)
	        {
	        	if (real_len->n->_value > dest_size)
		        {
	        		LOG_DEBUG("  [CheckRead] !!! OVERFLOW DETECTED !!!\n");
	        		qstring msg;
	        		msg.cat_sprnt("Read Overflow: Read %llu > Dst %llu", static_cast<unsigned long long>(real_len->n->_value), static_cast<unsigned long long>(dest_size));
	        		m_results->emplace_back(call->ea, "Stack Overflow", msg.c_str(), RiskLevel::CRITICAL);
		        }
	        }
            // len Ϊ�������ӱ���ʽ���޷�ȷ����С
            else
            {
                LOG_DEBUG("  [CheckRead] !!! POSSIBLE OVERFLOW DETECTED !!!\n");
                qstring msg;
                msg.cat_sprnt("Potential Overflow: Read variable size into fixed buf (%llu)", static_cast<unsigned long long>(dest_size));
                m_results->emplace_back(call->ea, "Variable Size Read", msg.c_str(), RiskLevel::HIGH);
			}

        }
    }
};
