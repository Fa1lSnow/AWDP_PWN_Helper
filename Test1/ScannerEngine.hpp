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
		// ��ȡ��������
		qstring func_name;
		get_func_name(&func_name, cfunc->entry_ea);

		// ��ʾ����������������� "main"���򱨸�һ�������©��
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

// ɨ��������
class ScannerEngine
{
private:
	// ̽�����б�
	std::vector<std::unique_ptr<IVulnDetector>> detectors;

public:
	ScannerEngine()
	{
		RegisterDetector(std::make_unique<StackDetector>());
		RegisterDetector(std::make_unique<FormatStringDetector>());
	}

	~ScannerEngine() = default;

	/**
	 * ע��һ���µ�©ɨ
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
		// ��鲢��ʼ�� Hex-Rays ���
		if (!init_hexrays_plugin())
		{
			msg("Hex-Rays decompiler is not available.\n");
			ask_yn(0, "Hex-Rays Decompiler is required.\nDo you have a valid license?");
			return;
		}

		
		size_t func_count = get_func_qty();
		msg("Starting scan on %zu functions...\n", func_count);

		show_wait_box("Starting scan...");

		// ��ʱ�����ڿ���ˢ�¼��
		auto last_update_time = std::chrono::steady_clock::now();


		// �������к���
		for (size_t i = 0; i < func_count; i ++)
		{

			if (user_cancelled())
			{
				msg("Scan cancelled by user\n");
				break;
			}

			// ��ȡ�������
			func_t* pFunc = getn_func(i);
			if (!pFunc)
			{
				continue;
			}

			// ����plt��
			qstring seg_name;
			get_segm_name(&seg_name, getseg(pFunc->start_ea));
			if (seg_name == ".plt" || seg_name == ".plt.got" || seg_name == ".plt.sec")
			{
				continue;
			}

			// ���� PLT���⺯����Thunk ���������غ���
			if (pFunc->flags & (FUNC_LIB | FUNC_THUNK | FUNC_HIDDEN))
			{
				continue;
			}

			// ���� extern �� data ��
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

			// 100 ms ˢ��һ��UI
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
