#pragma once

#include <hexrays.hpp>
#include <unordered_map>
#include <unordered_set>
#include <functional>
#include <string>
#include <cctype>
#include <vector>
#include <limits>
#include "IDetector.hpp"

#ifdef _DEBUG
#define LOG_DEBUG(...) msg(__VA_ARGS__)
#else
#define LOG_DEBUG(...)
#endif

struct VarInterval
{
    int64_t lo = std::numeric_limits<int64_t>::min();
    int64_t hi = std::numeric_limits<int64_t>::max();

    bool IsConstrained() const
    {
        return lo != std::numeric_limits<int64_t>::min() || hi != std::numeric_limits<int64_t>::max();
    }

    void Intersect(const VarInterval& other)
    {
        if (other.lo > lo) lo = other.lo;
        if (other.hi < hi) hi = other.hi;
    }
};

struct BranchConstraint
{
    int var_idx = -1;
    VarInterval interval;
};

class StackDetector : public IVulnDetector, public ctree_visitor_t
{
private:
    using handlerFunc = std::function<void(cexpr_t*)>;

    VulnList* m_results;
    cfunc_t* m_cfunc;
    std::unordered_map<std::string, handlerFunc> m_dispatch_map;
    std::unordered_set<int> m_boundary_full_copy_vars;
    std::unordered_set<int> m_bytewise_read_ptr_vars;
    std::unordered_set<int> m_incremented_ptr_vars;
    std::unordered_set<int> m_byte_input_char_vars;
    std::vector<BranchConstraint> m_constraint_stack;
    std::unordered_set<ea_t> m_reported_index_bound_sites;
    std::unordered_map<int, int64_t> m_global_upper_bounds;

public:
    StackDetector() : ctree_visitor_t(CV_FAST)
    {
        // 注册并分发各类危险调用检测器
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

        auto check_memmove = [this](cexpr_t* e) { CheckMemcpy(e); };
        m_dispatch_map["memmove"] = check_memmove;
        m_dispatch_map["_memmove"] = check_memmove;
        m_dispatch_map[".memmove"] = check_memmove;

        auto check_read = [this](cexpr_t* e) { CheckRead(e); };
        m_dispatch_map["read"] = check_read;
        m_dispatch_map["_read"] = check_read;
        m_dispatch_map[".read"] = check_read;

        auto check_recv = [this](cexpr_t* e) { CheckRead(e); };
        m_dispatch_map["recv"] = check_recv;
        m_dispatch_map["_recv"] = check_recv;
        m_dispatch_map[".recv"] = check_recv;

        auto check_snprintf = [this](cexpr_t* e) { CheckSnprintf(e); };
        m_dispatch_map["snprintf"] = check_snprintf;
        m_dispatch_map["_snprintf"] = check_snprintf;
        m_dispatch_map[".snprintf"] = check_snprintf;
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
        m_boundary_full_copy_vars.clear();
        m_bytewise_read_ptr_vars.clear();
        m_incremented_ptr_vars.clear();
        m_byte_input_char_vars.clear();
        m_constraint_stack.clear();
        m_reported_index_bound_sites.clear();
        m_global_upper_bounds.clear();
        this->apply_to(&cfunc->body, nullptr);
    }

protected:
    // 剥离 cast 
    cexpr_t* SkipCasts(cexpr_t* expr)
    {
        cexpr_t* cur = expr;
        int depth = 0;
        while (cur != nullptr && cur->op == cot_cast && depth < 16)
        {
            cur = cur->x;
            ++depth;
        }
        return cur;
    }

    bool IsSupportedCompareOp(int op) const
    {
        return op == cot_sle || op == cot_slt || op == cot_sge || op == cot_sgt
            || op == cot_ule || op == cot_ult || op == cot_uge || op == cot_ugt;
    }

    virtual int idaapi visit_expr(cexpr_t* expr) override
    {
        if (expr == nullptr) return 0;

        if (IsSupportedCompareOp(expr->op))
        {
            TrackGlobalUpperBound(expr);
        }

        if ((expr->op == cot_preinc || expr->op == cot_postinc) && expr->x != nullptr)
        {
            cexpr_t* inc_target = SkipCasts(expr->x);
            if (inc_target != nullptr && inc_target->op == cot_var)
            {
                m_incremented_ptr_vars.insert(inc_target->v.idx);
            }
            return 0;
        }

        if (expr->op == cot_asg)
        {
            TrackPointerIncrement(expr);
            TrackByteInputDataflow(expr);
            CheckOffByNullWrite(expr);
            CheckIndexedAccessBound(expr);
            return 0;
        }

        if (expr->op != cot_call || expr->x == nullptr) return 0;

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

        TrackByteReadPointer(name, expr);

        return 0;
    }

    virtual int idaapi visit_insn(cinsn_t* insn) override
    {
        if (insn == nullptr) return 0;

        if (insn->op == cit_for && insn->cfor != nullptr)
        {
            cfor_t* cfor = insn->cfor;
            if (cfor->expr.op != cot_empty && IsSupportedCompareOp(cfor->expr.op))
            {
                TrackGlobalUpperBound(&cfor->expr);
            }
            return 0;
        }

        if (insn->op == cit_while && insn->cwhile != nullptr)
        {
            cwhile_t* cwhile = insn->cwhile;
            if (cwhile->expr.op != cot_empty && IsSupportedCompareOp(cwhile->expr.op))
            {
                TrackGlobalUpperBound(&cwhile->expr);
            }
            return 0;
        }

        if (insn->op == cit_do && insn->cdo != nullptr)
        {
            cdo_t* cdo = insn->cdo;
            if (cdo->expr.op != cot_empty && IsSupportedCompareOp(cdo->expr.op))
            {
                TrackGlobalUpperBound(&cdo->expr);
            }
            return 0;
        }

        if (insn->op == cit_if && insn->cif != nullptr)
        {
            cif_t* cif = insn->cif;
            if (cif->expr.op != cot_empty)
            {
                TrackGlobalUpperBoundRecursive(&cif->expr);

                std::vector<BranchConstraint> constraints;
                ExtractConstraintsFromCondition(&cif->expr, true, constraints);

                for (const auto& c : constraints)
                {
                    m_constraint_stack.push_back(c);
                }

                if (cif->ithen != nullptr)
                {
                    this->apply_to(cif->ithen, nullptr);
                }

                for (size_t i = 0; i < constraints.size(); ++i)
                {
                    m_constraint_stack.pop_back();
                }

                if (cif->ielse != nullptr)
                {
                    std::vector<BranchConstraint> else_constraints;
                    ExtractConstraintsFromCondition(&cif->expr, false, else_constraints);

                    for (const auto& c : else_constraints)
                    {
                        m_constraint_stack.push_back(c);
                    }

                    this->apply_to(cif->ielse, nullptr);

                    for (size_t i = 0; i < else_constraints.size(); ++i)
                    {
                        m_constraint_stack.pop_back();
                    }
                }

                this->prune_now();
                return 0;
            }
        }

        return 0;
    }

private:
    uint64_t GetStackBufferSizeByIdx(int idx)
    {
        if (idx < 0 || m_cfunc == nullptr)
        {
            return 0;
        }

        lvars_t* lvars_ptr = m_cfunc->get_lvars();
        if (!lvars_ptr || static_cast<size_t>(idx) >= lvars_ptr->size())
        {
            return 0;
        }

        lvar_t* var = &(*lvars_ptr)[idx];
        if (var && var->type().is_array())
        {
            return var->type().get_size();
        }
        return 0;
    }

    uint64_t GetStackBufferSize(cexpr_t* arg_expr)
    {
        // 剥离 cats
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

    int GetStackBufferVarIdx(cexpr_t* arg_expr)
    {
        cexpr_t* real_expr = SkipCasts(arg_expr);
        if (real_expr == nullptr)
        {
            return -1;
        }

        if (real_expr->op == cot_ref && real_expr->x != nullptr && real_expr->x->op == cot_var)
        {
            return real_expr->x->v.idx;
        }

        if (real_expr->op == cot_var)
        {
            return real_expr->v.idx;
        }

        if (real_expr->op == cot_ref && real_expr->x != nullptr && real_expr->x->op == cot_idx)
        {
            if (real_expr->x->x != nullptr && real_expr->x->x->op == cot_var)
            {
                return real_expr->x->x->v.idx;
            }
        }

        return -1;
    }

    int GetSimpleVarIdx(cexpr_t* expr)
    {
        cexpr_t* real = SkipCasts(expr);
        if (real == nullptr)
        {
            return -1;
        }

        if (real->op == cot_var)
        {
            return real->v.idx;
        }

        if (real->op == cot_ref && real->x != nullptr && real->x->op == cot_var)
        {
            return real->x->v.idx;
        }

        return -1;
    }

    bool TryGetU64Const(cexpr_t* expr, uint64_t* out_value)
    {
        if (out_value == nullptr)
        {
            return false;
        }

        cexpr_t* real = SkipCasts(expr);
        if (real == nullptr || real->op != cot_num || real->n == nullptr)
        {
            return false;
        }

        *out_value = real->n->_value;
        return true;
    }

    bool IsVarVsConstCompare(cexpr_t* expr, int* out_var_idx, uint64_t* out_const, bool* out_var_on_left = nullptr)
    {
        if (expr == nullptr || !IsSupportedCompareOp(expr->op) || expr->x == nullptr || expr->y == nullptr || out_var_idx == nullptr || out_const == nullptr)
        {
            return false;
        }

        cexpr_t* left = SkipCasts(expr->x);
        cexpr_t* right = SkipCasts(expr->y);
        if (left == nullptr || right == nullptr)
        {
            return false;
        }

        uint64_t right_const = 0;
        if (left->op == cot_var && TryGetU64Const(right, &right_const))
        {
            *out_var_idx = left->v.idx;
            *out_const = right_const;
            if (out_var_on_left != nullptr)
            {
                *out_var_on_left = true;
            }
            return true;
        }

        uint64_t left_const = 0;
        if (TryGetU64Const(left, &left_const) && right->op == cot_var)
        {
            *out_var_idx = right->v.idx;
            *out_const = left_const;
            if (out_var_on_left != nullptr)
            {
                *out_var_on_left = false;
            }
            return true;
        }

        return false;
    }

    void ExtractConstraintsFromCondition(cexpr_t* cond, bool branch_taken, std::vector<BranchConstraint>& out)
    {
        if (cond == nullptr)
        {
            return;
        }

        if (branch_taken && cond->op == cot_land && cond->x != nullptr && cond->y != nullptr)
        {
            ExtractConstraintsFromCondition(cond->x, true, out);
            ExtractConstraintsFromCondition(cond->y, true, out);
            return;
        }

        if (!branch_taken && cond->op == cot_lor && cond->x != nullptr && cond->y != nullptr)
        {
            ExtractConstraintsFromCondition(cond->x, false, out);
            ExtractConstraintsFromCondition(cond->y, false, out);
            return;
        }

        BranchConstraint constraint;
        if (ExtractSingleConstraint(cond, branch_taken, constraint))
        {
            out.push_back(constraint);
        }
    }

    bool ExtractSingleConstraint(cexpr_t* cond, bool branch_taken, BranchConstraint& out)
    {
        if (cond == nullptr)
        {
            return false;
        }

        if (!IsSupportedCompareOp(cond->op))
        {
            return false;
        }

        int var_idx = -1;
        uint64_t cst = 0;
        bool var_on_left = true;
        if (!IsVarVsConstCompare(cond, &var_idx, &cst, &var_on_left))
        {
            return false;
        }

        out.var_idx = var_idx;
        out.interval = VarInterval{};
        int64_t c = static_cast<int64_t>(cst);

        ctype_t effective_op = cond->op;
        if (!var_on_left)
        {
            switch (cond->op)
            {
            case cot_slt: effective_op = cot_sgt; break;
            case cot_sle: effective_op = cot_sge; break;
            case cot_sgt: effective_op = cot_slt; break;
            case cot_sge: effective_op = cot_sle; break;
            case cot_ult: effective_op = cot_ugt; break;
            case cot_ule: effective_op = cot_uge; break;
            case cot_ugt: effective_op = cot_ult; break;
            case cot_uge: effective_op = cot_ule; break;
            default: break;
            }
        }

        if (branch_taken)
        {
            switch (effective_op)
            {
            case cot_slt: case cot_ult:
                out.interval.hi = c - 1;
                break;
            case cot_sle: case cot_ule:
                out.interval.hi = c;
                break;
            case cot_sgt: case cot_ugt:
                out.interval.lo = c + 1;
                break;
            case cot_sge: case cot_uge:
                out.interval.lo = c;
                break;
            default:
                return false;
            }
        }
        else
        {
            switch (effective_op)
            {
            case cot_slt: case cot_ult:
                out.interval.lo = c;
                break;
            case cot_sle: case cot_ule:
                out.interval.lo = c + 1;
                break;
            case cot_sgt: case cot_ugt:
                out.interval.hi = c;
                break;
            case cot_sge: case cot_uge:
                out.interval.hi = c - 1;
                break;
            default:
                return false;
            }
        }

        return true;
    }

    VarInterval GetActiveIntervalForVar(int var_idx) const
    {
        VarInterval result;
        for (const auto& constraint : m_constraint_stack)
        {
            if (constraint.var_idx == var_idx)
            {
                result.Intersect(constraint.interval);
            }
        }
        return result;
    }

    void TrackGlobalUpperBoundRecursive(cexpr_t* cond)
    {
        if (cond == nullptr)
        {
            return;
        }

        if (cond->op == cot_land && cond->x != nullptr && cond->y != nullptr)
        {
            TrackGlobalUpperBoundRecursive(cond->x);
            TrackGlobalUpperBoundRecursive(cond->y);
            return;
        }

        if (IsSupportedCompareOp(cond->op))
        {
            TrackGlobalUpperBound(cond);
        }
    }

    void TrackGlobalUpperBound(cexpr_t* cmp)
    {
        if (cmp == nullptr || cmp->x == nullptr || cmp->y == nullptr)
        {
            return;
        }

        int var_idx = -1;
        uint64_t cst = 0;
        bool var_on_left = true;
        if (!IsVarVsConstCompare(cmp, &var_idx, &cst, &var_on_left))
        {
            return;
        }

        int64_t c = static_cast<int64_t>(cst);
        ctype_t effective_op = cmp->op;
        if (!var_on_left)
        {
            switch (cmp->op)
            {
            case cot_slt: effective_op = cot_sgt; break;
            case cot_sle: effective_op = cot_sge; break;
            case cot_sgt: effective_op = cot_slt; break;
            case cot_sge: effective_op = cot_sle; break;
            case cot_ult: effective_op = cot_ugt; break;
            case cot_ule: effective_op = cot_uge; break;
            case cot_ugt: effective_op = cot_ult; break;
            case cot_uge: effective_op = cot_ule; break;
            default: break;
            }
        }

        int64_t potential_max = -1;
        switch (effective_op)
        {
        case cot_sgt: case cot_ugt:
            potential_max = c;
            break;
        case cot_sge: case cot_uge:
            potential_max = c - 1;
            break;
        case cot_slt: case cot_ult:
            potential_max = c - 1;
            break;
        case cot_sle: case cot_ule:
            potential_max = c;
            break;
        default:
            return;
        }

        if (potential_max >= 0)
        {
            auto it = m_global_upper_bounds.find(var_idx);
            if (it == m_global_upper_bounds.end() || potential_max > it->second)
            {
                m_global_upper_bounds[var_idx] = potential_max;
            }
        }
    }

    int ExtractScaledIndexVarIdx(cexpr_t* expr)
    {
        cexpr_t* real = SkipCasts(expr);
        if (real == nullptr)
        {
            return -1;
        }

        if (real->op == cot_var)
        {
            return real->v.idx;
        }

        if (real->op == cot_mul && real->x != nullptr && real->y != nullptr)
        {
            cexpr_t* lx = SkipCasts(real->x);
            cexpr_t* ly = SkipCasts(real->y);
            if (lx == nullptr || ly == nullptr)
            {
                return -1;
            }

            if (lx->op == cot_var && ly->op == cot_num)
            {
                return lx->v.idx;
            }
            if (ly->op == cot_var && lx->op == cot_num)
            {
                return ly->v.idx;
            }
        }

        if (real->op == cot_shl && real->x != nullptr && real->y != nullptr)
        {
            cexpr_t* lx = SkipCasts(real->x);
            cexpr_t* ly = SkipCasts(real->y);
            if (lx != nullptr && lx->op == cot_var && ly != nullptr && ly->op == cot_num)
            {
                return lx->v.idx;
            }
        }

        return -1;
    }

    struct IndexedWriteInfo
    {
        int index_var_idx = -1;
        int base_var_idx = -1;
    };

    int ExtractIndexedWriteVarIdx(cexpr_t* lhs)
    {
        IndexedWriteInfo info = ExtractIndexedWriteInfo(lhs);
        return info.index_var_idx;
    }

    IndexedWriteInfo ExtractIndexedWriteInfo(cexpr_t* lhs)
    {
        IndexedWriteInfo result;
        cexpr_t* real_lhs = SkipCasts(lhs);
        if (real_lhs == nullptr)
        {
            return result;
        }

        if (real_lhs->op == cot_idx && real_lhs->x != nullptr && real_lhs->y != nullptr)
        {
            cexpr_t* idx = SkipCasts(real_lhs->y);
            if (idx != nullptr && idx->op == cot_var)
            {
                result.index_var_idx = idx->v.idx;
            }
            cexpr_t* base = SkipCasts(real_lhs->x);
            if (base != nullptr && base->op == cot_var)
            {
                result.base_var_idx = base->v.idx;
            }
            return result;
        }

        if (real_lhs->op != cot_ptr || real_lhs->x == nullptr)
        {
            return result;
        }

        cexpr_t* addr = SkipCasts(real_lhs->x);
        if (addr == nullptr)
        {
            return result;
        }

        if (addr->op == cot_var)
        {
            return result;
        }

        if ((addr->op == cot_add || addr->op == cot_sub) && addr->x != nullptr && addr->y != nullptr)
        {
            cexpr_t* side_x = SkipCasts(addr->x);
            cexpr_t* side_y = SkipCasts(addr->y);

            int idx_from_x = ExtractScaledIndexVarIdx(addr->x);
            int idx_from_y = ExtractScaledIndexVarIdx(addr->y);

            if (idx_from_x >= 0)
            {
                result.index_var_idx = idx_from_x;
                if (side_y != nullptr && side_y->op == cot_var)
                {
                    result.base_var_idx = side_y->v.idx;
                }
            }
            else if (idx_from_y >= 0)
            {
                result.index_var_idx = idx_from_y;
                if (side_x != nullptr && side_x->op == cot_var)
                {
                    result.base_var_idx = side_x->v.idx;
                }
            }
            return result;
        }

        result.index_var_idx = ExtractScaledIndexVarIdx(addr);
        return result;
    }

    const char* GetLocalVarName(int idx) const
    {
        if (m_cfunc == nullptr)
        {
            return nullptr;
        }

        lvars_t* lvars_ptr = m_cfunc->get_lvars();
        if (lvars_ptr == nullptr || idx < 0 || static_cast<size_t>(idx) >= lvars_ptr->size())
        {
            return nullptr;
        }

        return (*lvars_ptr)[idx].name.c_str();
    }

    void CheckIndexedAccessBound(cexpr_t* asg)
    {
        if (m_results == nullptr || asg == nullptr || asg->x == nullptr)
        {
            return;
        }

        IndexedWriteInfo write_info = ExtractIndexedWriteInfo(asg->x);
        if (write_info.index_var_idx < 0)
        {
            return;
        }

        VarInterval branch_interval = GetActiveIntervalForVar(write_info.index_var_idx);
        bool has_branch_constraint = branch_interval.IsConstrained();

        int64_t global_upper = std::numeric_limits<int64_t>::max();
        auto git = m_global_upper_bounds.find(write_info.index_var_idx);
        if (git != m_global_upper_bounds.end())
        {
            global_upper = git->second;
        }
        bool has_global_bound = (global_upper != std::numeric_limits<int64_t>::max());

        if (!has_branch_constraint && !has_global_bound)
        {
            return;
        }

        int64_t effective_hi = std::numeric_limits<int64_t>::max();
        if (has_branch_constraint && has_global_bound)
        {
            effective_hi = std::min(branch_interval.hi, global_upper);
        }
        else if (has_branch_constraint)
        {
            effective_hi = branch_interval.hi;
        }
        else
        {
            effective_hi = global_upper;
        }

        uint64_t buf_size = 0;
        if (write_info.base_var_idx >= 0)
        {
            buf_size = GetStackBufferSizeByIdx(write_info.base_var_idx);
        }

        constexpr int64_t kUnknownBufSafeBoundThreshold = 16;

        if (buf_size > 0)
        {
            if (has_branch_constraint && effective_hi >= 0 && static_cast<uint64_t>(effective_hi) < buf_size)
            {
                return;
            }
            if (!has_branch_constraint && has_global_bound && static_cast<uint64_t>(effective_hi) < buf_size)
            {
                return;
            }
        }
        else
        {
            if (has_branch_constraint && effective_hi >= 0 && effective_hi < kUnknownBufSafeBoundThreshold)
            {
                return;
            }
        }

        if (m_reported_index_bound_sites.find(asg->ea) != m_reported_index_bound_sites.end())
        {
            return;
        }

        uint64_t rhs_const = 0;
        const bool null_write = TryGetU64Const(asg->y, &rhs_const) && rhs_const == 0;

        // If this is a null write with an explicit branch constraint (e.g., if (idx <= N) { ptr[idx] = 0; }),
        // this is intentional null-termination, not an off-by-null bug.
        // Only flag null writes when there's NO branch constraint protecting them,
        // or when we have a known buffer size that's being exceeded.
        if (null_write && has_branch_constraint && buf_size == 0)
        {
            // Explicit guard + null terminator + unknown buffer = intentional pattern, not a bug
            return;
        }

        int64_t reported_bound = effective_hi;
        if (reported_bound == std::numeric_limits<int64_t>::max() && branch_interval.lo > 0)
        {
            reported_bound = branch_interval.lo;
        }

        const char* name = GetLocalVarName(write_info.index_var_idx);
        qstring msg;
        if (name != nullptr && name[0] != '\0')
        {
            if (null_write)
            {
                msg.cat_sprnt("Potential off-by-null indexed write: '%s' may reach %lld before writing terminator 0.",
                    name,
                    static_cast<long long>(reported_bound));
            }
            else
            {
                msg.cat_sprnt("Potential off-by-one indexed access: '%s' may reach %lld before array write.",
                    name,
                    static_cast<long long>(reported_bound));
            }
        }
        else
        {
            if (null_write)
            {
                msg.cat_sprnt("Potential off-by-null indexed write: index variable may reach %lld before writing terminator 0.",
                    static_cast<long long>(reported_bound));
            }
            else
            {
                msg.cat_sprnt("Potential off-by-one indexed access: index variable may reach %lld before array write.",
                    static_cast<long long>(reported_bound));
            }
        }

        m_results->emplace_back(asg->ea,
            null_write ? "Potential Off-by-Null" : "Potential Off-by-One",
            msg.c_str(),
            RiskLevel::HIGH,
            null_write
                ? "Patch: enforce index < capacity before terminator write and keep null terminator inside allocated range."
                : "Patch: tighten guard to enforce index < capacity (replace > with >= on reject paths or <= with < on allow paths) and validate index before write.",
            PatchAction::NONE);

        m_reported_index_bound_sites.insert(asg->ea);
    }

    static std::string NormalizeSymbol(std::string name)
    {
        for (char& ch : name)
        {
            ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
        }

        size_t at = name.find('@');
        if (at != std::string::npos)
        {
            name = name.substr(0, at);
        }

        while (!name.empty() && (name[0] == '_' || name[0] == '.'))
        {
            name.erase(0, 1);
        }

        const char* kPrefixes[] = {
            "sym.imp.",
            "__imp_",
            "imp_",
            "j_",
            "gi_",
            "io_",
            "isoc99_",
            "__gi_",
            "__io_",
            "__isoc99_"
        };

        bool stripped = true;
        while (stripped)
        {
            stripped = false;
            for (const char* p : kPrefixes)
            {
                std::string pref(p);
                if (name.rfind(pref, 0) == 0)
                {
                    name.erase(0, pref.size());
                    stripped = true;
                }
            }
            while (!name.empty() && (name[0] == '_' || name[0] == '.'))
            {
                name.erase(0, 1);
                stripped = true;
            }
        }

        return name;
    }

    bool IsGetcLike(const std::string& name) const
    {
        const std::string n = NormalizeSymbol(name);
        return n == "getc" || n == "fgetc" || n == "getchar"
            || n == "getc_unlocked" || n == "fgetc_unlocked"
            || n == "io_getc" || n == "_io_getc";
    }

    bool GetCallNameFromExpr(cexpr_t* call, std::string& out_name) const
    {
        if (call == nullptr || call->op != cot_call || call->x == nullptr)
        {
            return false;
        }

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
        return !out_name.empty();
    }

    int GetPointerWriteVarIdx(cexpr_t* lhs, bool* out_incremented = nullptr)
    {
        if (out_incremented != nullptr)
        {
            *out_incremented = false;
        }

        cexpr_t* real_lhs = SkipCasts(lhs);
        if (real_lhs == nullptr || real_lhs->op != cot_ptr || real_lhs->x == nullptr)
        {
            return -1;
        }

        cexpr_t* ptr_expr = SkipCasts(real_lhs->x);
        if (ptr_expr == nullptr)
        {
            return -1;
        }

        if ((ptr_expr->op == cot_postinc || ptr_expr->op == cot_preinc) && ptr_expr->x != nullptr)
        {
            cexpr_t* base = SkipCasts(ptr_expr->x);
            if (base != nullptr && base->op == cot_var)
            {
                if (out_incremented != nullptr)
                {
                    *out_incremented = true;
                }
                return base->v.idx;
            }
        }

        if (ptr_expr->op == cot_var)
        {
            return ptr_expr->v.idx;
        }

        if (ptr_expr->op == cot_idx && ptr_expr->x != nullptr)
        {
            cexpr_t* base = SkipCasts(ptr_expr->x);
            cexpr_t* idx = SkipCasts(ptr_expr->y);
            if (base != nullptr && base->op == cot_var)
            {
                if (idx == nullptr || (idx->op == cot_num && idx->n->_value == 0))
                {
                    return base->v.idx;
                }
            }
        }

        return -1;
    }

    void TrackByteInputDataflow(cexpr_t* asg)
    {
        if (asg == nullptr || asg->x == nullptr || asg->y == nullptr)
        {
            return;
        }

        int lhs_var_idx = GetSimpleVarIdx(asg->x);
        cexpr_t* rhs = SkipCasts(asg->y);
        if (rhs == nullptr)
        {
            return;
        }

        if (lhs_var_idx >= 0)
        {
            if (rhs->op == cot_var && m_byte_input_char_vars.find(rhs->v.idx) != m_byte_input_char_vars.end())
            {
                m_byte_input_char_vars.insert(lhs_var_idx);
            }
            else if (rhs->op == cot_call)
            {
                std::string call_name;
                if (GetCallNameFromExpr(rhs, call_name) && IsGetcLike(call_name))
                {
                    m_byte_input_char_vars.insert(lhs_var_idx);
                }
            }
        }

        bool write_with_inc = false;
        int ptr_idx = GetPointerWriteVarIdx(asg->x, &write_with_inc);
        if (ptr_idx < 0)
        {
            return;
        }

        bool byte_src = false;
        if (rhs->op == cot_var && m_byte_input_char_vars.find(rhs->v.idx) != m_byte_input_char_vars.end())
        {
            byte_src = true;
        }
        else if (rhs->op == cot_call)
        {
            std::string call_name;
            if (GetCallNameFromExpr(rhs, call_name) && IsGetcLike(call_name))
            {
                byte_src = true;
            }
        }

        if (byte_src)
        {
            m_bytewise_read_ptr_vars.insert(ptr_idx);
            if (write_with_inc)
            {
                m_incremented_ptr_vars.insert(ptr_idx);
            }
        }
    }

    void TrackByteReadPointer(const std::string& name, cexpr_t* call)
    {
        if (call == nullptr || call->a == nullptr || call->a->size() < 3)
        {
            return;
        }

        if (name != "read" && name != "_read" && name != ".read" && name != "recv" && name != "_recv" && name != ".recv")
        {
            return;
        }

        cexpr_t* len_expr = SkipCasts(&(*call->a)[2]);
        if (len_expr == nullptr || len_expr->op != cot_num || len_expr->n->_value != 1)
        {
            return;
        }

        int ptr_idx = GetSimpleVarIdx(&(*call->a)[1]);
        if (ptr_idx >= 0)
        {
            m_bytewise_read_ptr_vars.insert(ptr_idx);
        }
    }

    void TrackPointerIncrement(cexpr_t* asg)
    {
        if (asg == nullptr || asg->x == nullptr || asg->y == nullptr)
        {
            return;
        }

        cexpr_t* lhs = SkipCasts(asg->x);
        cexpr_t* rhs = SkipCasts(asg->y);
        if (lhs == nullptr || rhs == nullptr || lhs->op != cot_var)
        {
            return;
        }

        if (rhs->op == cot_asgadd && rhs->x != nullptr && rhs->y != nullptr)
        {
            cexpr_t* rx = SkipCasts(rhs->x);
            cexpr_t* ry = SkipCasts(rhs->y);
            if (rx != nullptr && ry != nullptr && rx->op == cot_var && rx->v.idx == lhs->v.idx && ry->op == cot_num && ry->n->_value == 1)
            {
                m_incremented_ptr_vars.insert(lhs->v.idx);
            }
            return;
        }

        if (rhs->op != cot_add || rhs->x == nullptr || rhs->y == nullptr)
        {
            return;
        }

        cexpr_t* rx = SkipCasts(rhs->x);
        cexpr_t* ry = SkipCasts(rhs->y);
        if (rx == nullptr || ry == nullptr)
        {
            return;
        }

        if (rx->op == cot_var && rx->v.idx == lhs->v.idx && ry->op == cot_num && ry->n->_value == 1)
        {
            m_incremented_ptr_vars.insert(lhs->v.idx);
        }
    }

    void CheckGets(cexpr_t* call)
    {
        if (m_results == nullptr || call == nullptr || call->a == nullptr || call->a->size() < 1) return;
        m_results->emplace_back(call->ea,
            "Stack Overflow(Critical)",
            "Usage of 'gets'",
            RiskLevel::CRITICAL,
            "Patch: replace gets with fgets(buf, sizeof(buf), stdin); if binary-only, NOP this call and gate input path.",
            PatchAction::NOP_CALL);
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
			// 源为字符串字面量，可直接比较长度
            if (real_src->op == cot_str)
	        {
		        qstring content;
	        	if (real_src->string) content = real_src->string;
	        	if (content.length() == dest_size)
	        	{
	        		qstring msg;
	        		msg.cat_sprnt("Off-by-Null: strcpy writes trailing null one byte past %llu-byte buffer", static_cast<unsigned long long>(dest_size));
	        		m_results->emplace_back(call->ea,
	        			"Off-by-Null",
	        			msg.c_str(),
	        			RiskLevel::CRITICAL,
	        			"Patch: ensure destination capacity is source_len + 1, or use bounded copy and force terminator within bounds.",
	        			PatchAction::NOP_CALL);
	        	}
	        	else if (content.length() > dest_size)
	        	{
                    LOG_DEBUG("  [CheckRead] !!! OVERFLOW DETECTED !!!\n");
	        		qstring msg;
	        		msg.cat_sprnt("Strcpy Overflow: len %llu >= buf %llu", static_cast<unsigned long long>(content.length()), static_cast<unsigned long long>(dest_size));
	        		m_results->emplace_back(call->ea,
	        			"Stack Overflow(Critical)",
	        			msg.c_str(),
	        			RiskLevel::CRITICAL,
	        			"Patch: replace strcpy with strncpy/memcpy with explicit bound checks; or NOP this call as emergency mitigation.",
	        			PatchAction::NOP_CALL);
	        	}
	        }
            // 源为变量或复杂表达式，长度不确定
            else
            {
                LOG_DEBUG("  [CheckRead] !!! POSSIBLE OVERFLOW DETECTED !!!\n");
                qstring msg;
                msg.cat_sprnt("Risky Strcpy: Unknown source len into fixed buf (%llu)", static_cast<unsigned long long>(dest_size));
				m_results->emplace_back(call->ea,
					"Potential Stack Overflow",
					msg.c_str(),
					RiskLevel::HIGH,
					"Patch: enforce source length check before copy; prefer bounded API and validate destination capacity.",
					PatchAction::NOP_CALL);
			}
        }
    }

    void CheckMemcpy(cexpr_t* call)
    {
        if (m_results == nullptr || call == nullptr || call->a == nullptr || call->a->size() < 3) return;

        cexpr_t* dest = &(*call->a)[0];
        cexpr_t* src = &(*call->a)[1];
        cexpr_t* len = &(*call->a)[2];

        uint64_t dest_size = GetStackBufferSize(dest);
        uint64_t src_size = GetStackBufferSize(src);
        int dest_var_idx = GetStackBufferVarIdx(dest);
        cexpr_t* real_len = SkipCasts(len);
        if (real_len == nullptr)
        {
            return;
        }

        if (dest_size > 0)
        {
			// 长度为常量，可做精确边界判断
            if (real_len->op == cot_num)
	        {
                if (dest_size < UINT64_MAX && real_len->n->_value == dest_size + 1)
		        {
			        qstring msg;
			        msg.cat_sprnt("Off-by-One: copy %llu into %llu-byte buffer", static_cast<unsigned long long>(real_len->n->_value), static_cast<unsigned long long>(dest_size));
			        m_results->emplace_back(call->ea,
			        	"Off-by-One",
			        	msg.c_str(),
			        	RiskLevel::CRITICAL,
			        	"Patch: clamp length to destination size and reserve extra byte when a terminator is required.",
			        	PatchAction::CLAMP_SIZE_ARG,
			        	dest_size,
			        	2);
		        }
		        else if (real_len->n->_value == dest_size && dest_var_idx >= 0)
		        {
			        m_boundary_full_copy_vars.insert(dest_var_idx);
		        }
		        else if (real_len->n->_value > dest_size)
		        {
                    LOG_DEBUG("  [CheckRead] !!! OVERFLOW DETECTED !!!\n");
		        	qstring msg;
		        	msg.cat_sprnt("Memcpy Overflow: Copy %llu > Dst %llu", static_cast<unsigned long long>(real_len->n->_value), static_cast<unsigned long long>(dest_size));
		        	m_results->emplace_back(call->ea,
		        		"Stack Overflow",
		        		msg.c_str(),
		        		RiskLevel::CRITICAL,
		        		"Patch: clamp copy length to destination size and validate both source/destination bounds.",
		        		PatchAction::CLAMP_SIZE_ARG,
		        		dest_size,
		        		2);
		        }
	        }
			// 长度为变量或表达式，按高风险处理
            else if (real_len->op == cot_var)
            {
                int len_var_idx = real_len->v.idx;
                VarInterval interval = GetActiveIntervalForVar(len_var_idx);
                auto git = m_global_upper_bounds.find(len_var_idx);
                
                int64_t effective_upper = std::numeric_limits<int64_t>::max();
                if (interval.hi != std::numeric_limits<int64_t>::max())
                {
                    effective_upper = interval.hi;
                }
                if (git != m_global_upper_bounds.end() && git->second < effective_upper)
                {
                    effective_upper = git->second;
                }
                
                if (effective_upper != std::numeric_limits<int64_t>::max() 
                    && effective_upper >= 0 
                    && static_cast<uint64_t>(effective_upper) <= dest_size)
                {
                    return;
                }
                
                LOG_DEBUG("  [CheckRead] !!! POSSIBLE OVERFLOW DETECTED !!!\n");
                qstring msg;
                msg.cat_sprnt("Potential Overflow: Memcpy variable size into fixed buf (%llu)", static_cast<unsigned long long>(dest_size));
				m_results->emplace_back(call->ea,
					"Variable Size Memcpy",
					msg.c_str(),
					RiskLevel::HIGH,
					"Patch: validate runtime length <= destination size before memcpy.",
					PatchAction::NOP_CALL);
            }
            else
            {
                LOG_DEBUG("  [CheckRead] !!! POSSIBLE OVERFLOW DETECTED !!!\n");
                qstring msg;
                msg.cat_sprnt("Potential Overflow: Memcpy variable size into fixed buf (%llu)", static_cast<unsigned long long>(dest_size));
				m_results->emplace_back(call->ea,
					"Variable Size Memcpy",
					msg.c_str(),
					RiskLevel::HIGH,
					"Patch: validate runtime length <= destination size before memcpy.",
					PatchAction::NOP_CALL);
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
        int dest_var_idx = GetStackBufferVarIdx(dest);
        cexpr_t* real_len = SkipCasts(len);
        if (real_len == nullptr)
        {
            return;
        }

        LOG_DEBUG("  [CheckRead] DstSize: %llu, WriteLenOp: %d\n", static_cast<unsigned long long>(dest_size), real_len->op);

        if (dest_size > 0 )
        {
            // 长度为常量，可直接判断是否越界
            if (real_len->op == cot_num)
	        {
	        	if (dest_size < UINT64_MAX && real_len->n->_value == dest_size + 1)
		        {
		        	qstring msg;
		        	msg.cat_sprnt("Off-by-One: write %llu into %llu-byte buffer", static_cast<unsigned long long>(real_len->n->_value), static_cast<unsigned long long>(dest_size));
		        	m_results->emplace_back(call->ea,
		        		"Off-by-One",
		        		msg.c_str(),
		        		RiskLevel::CRITICAL,
		        		"Patch: enforce length <= destination buffer size before read/recv.",
		        		PatchAction::CLAMP_SIZE_ARG,
		        		dest_size,
		        		2);
		        }
	        	else if (real_len->n->_value == dest_size && dest_var_idx >= 0)
		        {
		        	m_boundary_full_copy_vars.insert(dest_var_idx);
		        }
	        	else if (real_len->n->_value > dest_size)
		        {
	        		LOG_DEBUG("  [CheckRead] !!! OVERFLOW DETECTED !!!\n");
	        		qstring msg;
	        		msg.cat_sprnt("Read Overflow: Read %llu > Dst %llu", static_cast<unsigned long long>(real_len->n->_value), static_cast<unsigned long long>(dest_size));
	        		m_results->emplace_back(call->ea,
	        			"Stack Overflow",
	        			msg.c_str(),
	        			RiskLevel::CRITICAL,
	        			"Patch: cap read length to destination buffer size and reject oversized requests.",
	        			PatchAction::CLAMP_SIZE_ARG,
	        			dest_size,
	        			2);
		        }
	        }
            // 长度为变量或表达式，无法静态确定上界
            else if (real_len->op == cot_var)
            {
                int len_var_idx = real_len->v.idx;
                VarInterval interval = GetActiveIntervalForVar(len_var_idx);
                auto git = m_global_upper_bounds.find(len_var_idx);
                
                int64_t effective_upper = std::numeric_limits<int64_t>::max();
                if (interval.hi != std::numeric_limits<int64_t>::max())
                {
                    effective_upper = interval.hi;
                }
                if (git != m_global_upper_bounds.end() && git->second < effective_upper)
                {
                    effective_upper = git->second;
                }
                
                if (effective_upper != std::numeric_limits<int64_t>::max() 
                    && effective_upper >= 0 
                    && static_cast<uint64_t>(effective_upper) <= dest_size)
                {
                    return;
                }
                
                LOG_DEBUG("  [CheckRead] !!! POSSIBLE OVERFLOW DETECTED !!!\n");
                qstring msg;
                msg.cat_sprnt("Potential Overflow: Read variable size into fixed buf (%llu)", static_cast<unsigned long long>(dest_size));
				m_results->emplace_back(call->ea,
					"Variable Size Read",
					msg.c_str(),
					RiskLevel::HIGH,
					"Patch: add explicit max-length guard before read/write into fixed-size buffer.",
					PatchAction::CLAMP_SIZE_ARG,
					dest_size,
					2);
			}
            else
            {
                LOG_DEBUG("  [CheckRead] !!! POSSIBLE OVERFLOW DETECTED !!!\n");
                qstring msg;
                msg.cat_sprnt("Potential Overflow: Read variable size into fixed buf (%llu)", static_cast<unsigned long long>(dest_size));
				m_results->emplace_back(call->ea,
					"Variable Size Read",
					msg.c_str(),
					RiskLevel::HIGH,
					"Patch: add explicit max-length guard before read/write into fixed-size buffer.",
					PatchAction::CLAMP_SIZE_ARG,
					dest_size,
					2);
			}

        }
    }

    void CheckSnprintf(cexpr_t* call)
    {
        if (m_results == nullptr || call == nullptr || call->a == nullptr || call->a->size() < 2) return;

        cexpr_t* dest = &(*call->a)[0];
        cexpr_t* size_arg = &(*call->a)[1];

        uint64_t dest_size = GetStackBufferSize(dest);
        cexpr_t* real_size = SkipCasts(size_arg);
        if (dest_size == 0 || real_size == nullptr || real_size->op != cot_num)
        {
            return;
        }

        const uint64_t n = real_size->n->_value;
        if (dest_size < UINT64_MAX && n == dest_size + 1)
        {
            qstring msg;
            msg.cat_sprnt("Off-by-One: snprintf bound %llu exceeds %llu-byte buffer by one", static_cast<unsigned long long>(n), static_cast<unsigned long long>(dest_size));
            m_results->emplace_back(call->ea,
                "Off-by-One",
                msg.c_str(),
                RiskLevel::CRITICAL,
                "Patch: pass exact destination size to snprintf and reserve terminator within bounds.",
                PatchAction::CLAMP_SIZE_ARG,
                dest_size,
                1);
        }
        else if (n > dest_size)
        {
            qstring msg;
            msg.cat_sprnt("snprintf bound overflow: %llu > %llu", static_cast<unsigned long long>(n), static_cast<unsigned long long>(dest_size));
            m_results->emplace_back(call->ea,
                "Stack Overflow",
                msg.c_str(),
                RiskLevel::CRITICAL,
                "Patch: ensure snprintf size argument is <= destination buffer size.",
                PatchAction::CLAMP_SIZE_ARG,
                dest_size,
                1);
        }
    }

    void CheckOffByNullWrite(cexpr_t* asg)
    {
        if (m_results == nullptr || asg == nullptr || asg->x == nullptr || asg->y == nullptr)
        {
            return;
        }

        cexpr_t* lhs = SkipCasts(asg->x);
        cexpr_t* rhs = SkipCasts(asg->y);
        if (lhs == nullptr || rhs == nullptr)
        {
            return;
        }

        if (rhs->op != cot_num || rhs->n->_value != 0)
        {
            return;
        }

        cexpr_t* base_expr = nullptr;
        cexpr_t* idx_expr = nullptr;
        int direct_ptr_var_idx = -1;

        if (lhs->op == cot_idx && lhs->x != nullptr && lhs->y != nullptr)
        {
            base_expr = lhs->x;
            idx_expr = lhs->y;
        }
        else if (lhs->op == cot_ptr && lhs->x != nullptr)
        {
            cexpr_t* ptr_base = SkipCasts(lhs->x);
            if (ptr_base != nullptr && ptr_base->op == cot_var)
            {
                direct_ptr_var_idx = ptr_base->v.idx;
                base_expr = ptr_base;
            }
            if (ptr_base != nullptr && (ptr_base->op == cot_add || ptr_base->op == cot_sub) && ptr_base->x != nullptr && ptr_base->y != nullptr)
            {
                base_expr = ptr_base->x;
                idx_expr = ptr_base->y;
            }
        }

        if (direct_ptr_var_idx >= 0 && idx_expr == nullptr)
        {
            if (m_bytewise_read_ptr_vars.find(direct_ptr_var_idx) != m_bytewise_read_ptr_vars.end()
                && m_incremented_ptr_vars.find(direct_ptr_var_idx) != m_incremented_ptr_vars.end())
            {
                m_results->emplace_back(asg->ea,
                    "Off-by-Null",
                    "Potential off-by-null: byte-wise input stream is written through pointer cursor and then null-terminated at current cursor position.",
                    RiskLevel::HIGH,
                    "Patch: stop write loop at max-1 and write terminator within allocated range.",
                    PatchAction::NONE);
            }
            return;
        }

        if (base_expr == nullptr || idx_expr == nullptr)
        {
            return;
        }

        int base_ptr_idx = GetSimpleVarIdx(base_expr);
        cexpr_t* raw_idx = SkipCasts(idx_expr);
        if (base_ptr_idx >= 0
            && raw_idx != nullptr
            && raw_idx->op == cot_num
            && raw_idx->n->_value == 0
            && m_bytewise_read_ptr_vars.find(base_ptr_idx) != m_bytewise_read_ptr_vars.end()
            && m_incremented_ptr_vars.find(base_ptr_idx) != m_incremented_ptr_vars.end())
        {
            m_results->emplace_back(asg->ea,
                "Off-by-Null",
                "Potential off-by-null: byte-wise input pointer is null-terminated via index form at current cursor position.",
                RiskLevel::HIGH,
                "Patch: reserve one extra byte for terminator and ensure growth condition guarantees space before final null write.",
                PatchAction::NONE);
            return;
        }

        uint64_t dest_size = GetStackBufferSize(base_expr);
        int dest_var_idx = GetStackBufferVarIdx(base_expr);
        cexpr_t* idx = SkipCasts(idx_expr);
        if (dest_size == 0 || idx == nullptr || idx->op != cot_num)
        {
            return;
        }

        if (idx->n->_value == dest_size)
        {
            qstring msg;
            msg.cat_sprnt("Off-by-Null: index %llu equals buffer size %llu in null-byte write", static_cast<unsigned long long>(idx->n->_value), static_cast<unsigned long long>(dest_size));
            RiskLevel risk = RiskLevel::HIGH;
            if (dest_var_idx >= 0 && m_boundary_full_copy_vars.find(dest_var_idx) != m_boundary_full_copy_vars.end())
            {
                risk = RiskLevel::CRITICAL;
            }
            m_results->emplace_back(asg->ea,
                "Off-by-Null",
                msg.c_str(),
                risk,
                "Patch: ensure terminating null is written at size-1 max, and keep index bounds strictly < size.",
                PatchAction::NONE);
        }
        else if (dest_size < UINT64_MAX && idx->n->_value == dest_size + 1)
        {
            qstring msg;
            msg.cat_sprnt("Off-by-One: index %llu writes one byte past %llu-byte buffer", static_cast<unsigned long long>(idx->n->_value), static_cast<unsigned long long>(dest_size));
            m_results->emplace_back(asg->ea,
                "Off-by-One",
                msg.c_str(),
                RiskLevel::CRITICAL,
                "Patch: clamp index to [0, size-1] and audit boundary checks for <= misuse.",
                PatchAction::NONE);
        }
    }
};
