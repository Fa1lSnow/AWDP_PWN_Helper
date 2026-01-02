#pragma once

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <funcs.hpp>
#include <hexrays.hpp>
#include <segment.hpp>
#include <chrono>

#include <vector>
#include "VulnData.hpp"
#include "IDetector.hpp"
#include "StackDetector.hpp"


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
		// 获取函数名称
		qstring func_name;
		get_func_name(&func_name, cfunc->entry_ea);

		// 简单示例：如果函数名包含 "main"，则报告一个假设的漏洞
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

// 扫描引擎类
class ScannerEngine
{
private:
	// 探测器列表
	std::vector<IVulnDetector*> detectors;

public:
	ScannerEngine()
	{
		//RegisterDetector(new DemoDetector());
		RegisterDetector(new StackDetector());
	}

	~ScannerEngine()
	{
		for (auto *d : detectors)
		{
			delete d;
		}
		detectors.clear();
	}

	/**
	 * 注册一个新的漏扫
	 */
	void RegisterDetector(IVulnDetector* detector)
	{
		if (detector)
		{
			detectors.push_back(detector);
		}
	}

	void ScanAll(VulnList& out_result)
	{
		// 检查并初始化 Hex-Rays 插件
		if (!init_hexrays_plugin())
		{
			msg("Hex-Rays decompiler is not available.\n");
			ask_yn(0, "Hex-Rays Decompiler is required.\nDo you have a valid license?");
			return;
		}

		
		size_t func_count = get_func_qty();
		msg("Starting scan on %zu functions...\n", func_count);

		show_wait_box("Starting scan...");

		// 计时器用于控制刷新间隔
		auto last_update_time = std::chrono::steady_clock::now();


		// 遍历所有函数
		for (size_t i = 0; i < func_count; i ++)
		{

			if (user_cancelled())
			{
				msg("Scan cancelled by user\n");
				break;
			}

			// 获取函数句柄
			func_t* pFunc = getn_func(i);
			if (!pFunc)
			{
				continue;
			}

			// 过滤plt段
			qstring seg_name;
			get_segm_name(&seg_name, getseg(pFunc->start_ea));
			if (seg_name == ".plt" || seg_name == ".plt.got" || seg_name == ".plt.sec")
			{
				continue;
			}

			// 过滤 PLT、库函数、Thunk 函数、隐藏函数
			if (pFunc->flags & (FUNC_LIB | FUNC_THUNK | FUNC_HIDDEN))
			{
				continue;
			}

			// 过滤 extern 和 data 段
			segment_t* seg = getseg(pFunc->start_ea);
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

			// 100 ms 刷新一次UI
			auto current_time = std::chrono::steady_clock::now();
			auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(current_time - last_update_time).count();

			if (elapsed_ms > 100)
			{
				msg("Scanning function %zu/%zu: %p", i + 1, func_count, pFunc->start_ea);
				last_update_time = current_time;
			}


			try
			{
				hexrays_failure_t hf;
				cfuncptr_t cfunc = decompile_func(pFunc, &hf, DECOMP_WARNINGS);

				if ( cfunc == nullptr)
				{
					continue;
				}

				for (auto* detector : detectors)
				{
					detector->RunAnalysis(cfunc, out_result);
				}
			}
			catch (...)
			{
				continue;
			}
		}


		hide_wait_box();
		msg("Scan finished. Found %zu entries.\n", out_result.size());
		qsleep(100);

	}

};