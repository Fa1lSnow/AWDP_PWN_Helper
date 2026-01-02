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
        // 注册回调
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
        m_results = &result;
        m_cfunc = cfunc;
        this->apply_to(&cfunc->body, nullptr);
    }

protected:
    // 剥离 cast 类型转换，找到核心节点
    cexpr_t* SkipCasts(cexpr_t* expr)
    {
        cexpr_t* cur = expr;
        while (cur->op == cot_cast)
        {
            cur = cur->x;
        }
        return cur;
    }

    virtual int idaapi visit_expr(cexpr_t* expr) override
    {
        if (expr->op != cot_call) return 0;

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
        // 剥离 Cast 
        cexpr_t* real_expr = SkipCasts(arg_expr);

        int idx = -1;

        // &buf (cot_ref -> cot_var)
        if (real_expr->op == cot_ref && real_expr->x->op == cot_var)
        {
            idx = real_expr->x->v.idx;
        }
        // buf (cot_var)
        else if (real_expr->op == cot_var)
        {
            idx = real_expr->v.idx;
        }
        // &buf[0] (cot_ref -> cot_idx -> cot_var)
        else if (real_expr->op == cot_ref && real_expr->x->op == cot_idx)
        {
            if (real_expr->x->x->op == cot_var)
            {
                idx = real_expr->x->x->v.idx;
            }
        }

        LOG_DEBUG("  [GetSize] Op: %d, Idx: %d\n", real_expr->op, idx);

        if (idx == -1 || m_cfunc == nullptr) return 0;

        lvars_t* lvars_ptr = m_cfunc->get_lvars();
        if (!lvars_ptr || idx >= lvars_ptr->size()) return 0;

        lvar_t* var = &(*lvars_ptr)[idx];
        if (var)
        {
            uint64_t size = 0;
            if (var->type().is_array())
            {
                size = var->type().get_size();
            }
            else
            {
                size = var->width;
            }
            LOG_DEBUG("  [GetSize] Found: %s, Size: %lld\n", var->name.c_str(), size);
            return size;
        }
        return 0;
    }

    void CheckGets(cexpr_t* call)
    {
        if (call->a->size() < 1) return;
        m_results->emplace_back(call->ea, "Stack Overflow(Critical)", "Usage of 'gets'", RiskLevel::CRITICAL);
    }

    void CheckStrcpy(cexpr_t* call)
    {
        if (call->a->size() < 2) return;

        cexpr_t* dest = &(*call->a)[0];
        cexpr_t* src = &(*call->a)[1];

        uint64_t dest_size = GetStackBufferSize(dest);
        cexpr_t* real_src = SkipCasts(src);

        if (dest_size > 0 && real_src->op == cot_str)
        {
            qstring content;
            if (real_src->string) content = real_src->string;
            if (content.length() >= dest_size)
            {
                qstring msg;
                msg.cat_sprnt("Strcpy Overflow: len %d >= buf %lld", content.length(), dest_size);
                m_results->emplace_back(call->ea, "Stack Overflow(Critical)", msg.c_str(), RiskLevel::CRITICAL);
            }
        }
    }

    void CheckMemcpy(cexpr_t* call)
    {
        if (call->a->size() < 3) return;

        cexpr_t* dest = &(*call->a)[0];
        cexpr_t* len = &(*call->a)[2];

        uint64_t dest_size = GetStackBufferSize(dest);
        cexpr_t* real_len = SkipCasts(len);

        if (dest_size > 0 && real_len->op == cot_num)
        {
            if (real_len->n->_value > dest_size)
            {
                qstring msg;
                msg.cat_sprnt("Memcpy Overflow: Copy %lld > Dst %lld", real_len->n->_value, dest_size);
                m_results->emplace_back(call->ea, "Stack Overflow", msg.c_str(), RiskLevel::CRITICAL);
            }
        }
    }

    void CheckRead(cexpr_t* call)
    {
        if (call->a->size() < 3) return;

        // read(fd, buf, len)
        cexpr_t* dest = &(*call->a)[1];
        cexpr_t* len = &(*call->a)[2];

        uint64_t dest_size = GetStackBufferSize(dest);
        cexpr_t* real_len = SkipCasts(len);

        LOG_DEBUG("  [CheckRead] DstSize: %lld, WriteLenOp: %d\n", dest_size, real_len->op);

        if (dest_size > 0 && real_len->op == cot_num)
        {
            if (real_len->n->_value > dest_size)
            {
                LOG_DEBUG("  [CheckRead] !!! OVERFLOW DETECTED !!!\n");
                qstring msg;
                msg.cat_sprnt("Read Overflow: Read %lld > Dst %lld", real_len->n->_value, dest_size);
                m_results->emplace_back(call->ea, "Stack Overflow", msg.c_str(), RiskLevel::CRITICAL);
            }
        }
    }
};