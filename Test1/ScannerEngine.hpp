#pragma once

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <funcs.hpp>
#include <hexrays.hpp>
#include <segment.hpp>
#include <chrono>
#include <exception>
#include <memory>

#include <vector>
#include "VulnData.hpp"
#include "IDetector.hpp"
#include "StackDetector.hpp"
#include "FormatStringDetector.hpp"
#include "AdvancedPwnDetectors.hpp"

//DEMO TEST
class DemoDetector : public IVulnDetector
{
public:
	virtual const char* getName() const override
	{
		return "Demo Vulnerability Detector";
	}

	virtual void RunAnalysis(cfunc_t* cfunc, VulnList& result) override
	{
		// 获取当前函数名
		qstring func_name;
		get_func_name(&func_name, cfunc->entry_ea);

		// 演示规则：函数名包含 main 时给出一条低风险示例项
		if (func_name.find("main") != qstring::npos)
		{
			result.push_back(VulnEntry(
				cfunc->entry_ea,
				"Demo Vulnerability",
				"Function name contains 'main', which is suspicious.",
				RiskLevel::LOW
			));
		}
	}
};

// 扫描引擎：统一遍历函数并分发给各检测器
class ScannerEngine
{
private:
	// 已注册检测器列表
	std::vector<std::unique_ptr<IVulnDetector>> detectors;

public:
	ScannerEngine()
	{
		RegisterDetector(std::make_unique<StackDetector>());
		RegisterDetector(std::make_unique<FormatStringDetector>());
		RegisterDetector(std::make_unique<HeapAndIntegerDetector>());
		RegisterDetector(std::make_unique<DangerousCallDetector>());
	}

	~ScannerEngine() = default;

	/**
	 * 注册一个新的漏洞检测器
	 */
	void RegisterDetector(std::unique_ptr<IVulnDetector> detector)
	{
		if (detector)
		{
			detectors.push_back(std::move(detector));
		}
	}

	void ScanAll(VulnList& out_result)
	{
		// 检查并初始化 Hex-Rays 反编译器
		if (!init_hexrays_plugin())
		{
			msg("Hex-Rays decompiler is not available.\n");
			ask_yn(0, "Hex-Rays Decompiler is required.\nDo you have a valid license?");
			return;
		}

		
		size_t func_count = get_func_qty();
		msg("Starting scan on %zu functions...\n", func_count);

		show_wait_box("Starting scan...");

		// 控制 UI 刷新节奏，避免输出过于频繁
		auto last_update_time = std::chrono::steady_clock::now();


		// 遍历数据库中的全部函数
		for (size_t i = 0; i < func_count; i ++)
		{

			if (user_cancelled())
			{
				msg("Scan cancelled by user\n");
				break;
			}

			// 获取函数对象
			func_t* pFunc = getn_func(i);
			if (!pFunc)
			{
				continue;
			}

			// 跳过 .plt 相关段
			segment_t* seg = getseg(pFunc->start_ea);
			if (seg == nullptr)
			{
				continue;
			}

			qstring seg_name;
			get_segm_name(&seg_name, seg);
			if (seg_name == ".plt" || seg_name == ".plt.got" || seg_name == ".plt.sec")
			{
				continue;
			}

			// 跳过导入/Thunk/隐藏函数
			if (pFunc->flags & (FUNC_LIB | FUNC_THUNK | FUNC_HIDDEN))
			{
				continue;
			}

			// 跳过 extern 与纯数据段
			if (seg)
			{
				if (seg->type == SEG_XTRN || seg->type == SEG_DATA)
				{
					continue;
				}
			}

			if (pFunc->size() < 5)
			{
				continue;
			}

			// 每 100ms 输出一次进度
			auto current_time = std::chrono::steady_clock::now();
			auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(current_time - last_update_time).count();

			if (elapsed_ms > 100)
			{
				msg("Scanning function %zu/%zu: %a\n", i + 1, func_count, pFunc->start_ea);
				last_update_time = current_time;
			}

			hexrays_failure_t hf;
			cfuncptr_t cfunc = decompile_func(pFunc, &hf, DECOMP_WARNINGS);

			if ( cfunc == nullptr)
			{
				continue;
			}

			for (const auto& detector : detectors)
			{
				try
				{
					detector->RunAnalysis(cfunc, out_result);
				}
				catch (const std::exception& e)
				{
					msg("Detector '%s' failed at %a: %s\n", detector->getName(), pFunc->start_ea, e.what());
				}
				catch (...)
				{
					msg("Detector '%s' failed at %a: unknown exception\n", detector->getName(), pFunc->start_ea);
				}
			}
		}


		hide_wait_box();
		msg("Scan finished. Found %zu entries.\n", out_result.size());
		qsleep(100);

	}

};
