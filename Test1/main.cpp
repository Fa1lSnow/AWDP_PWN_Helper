#define __EA64__

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <vector>
#include <string>

#include "VulnData.hpp"
#include "ScannerEngine.hpp"
#include "PatchEngine.hpp"

/**
 * ����UI������
 */
class VulnChooser : public chooser_t
{
public:
	static constexpr int kColumnWidthsEx[4] = {15, 20, 52, 46};
	static constexpr const char* kColumnHeadersEx[4] = {"Address", "Type", "Description", "Patch Suggestion"};

	// ©�������б�
	VulnList entries;

public:
	VulnChooser( const char* title)
		: chooser_t(CH_CAN_EDIT, 4, kColumnWidthsEx, kColumnHeadersEx, title)
	{
		#if defined(POPUP_EDIT)
		popup_names[POPUP_EDIT] = "One Click Patch";
		#endif
	}

	void ApplyPatchForIndex(size_t n)
	{
		if (n >= entries.size())
		{
			return;
		}

		const VulnEntry& entry = entries[n];
		if (!PatchEngine::CanAutoPatch(entry))
		{
			warning("[PwnHelper] Auto patch is unavailable for this finding.");
			return;
		}

		qstring preview;
		preview.cat_sprnt("Patch preview:\n%s\n\nApply click patch at %a now?", entry.patch_suggestion.c_str(), entry.address);

		int resp = ask_yn(1, "%s", preview.c_str());
		if (resp != 1)
		{
			return;
		}

		qstring patch_result;
		try
		{
			if (PatchEngine::ApplyPatch(entry, patch_result))
			{
				msg("[PwnHelper] Patch applied: %s\n", patch_result.c_str());
			}
			else
			{
				warning("[PwnHelper] Patch failed: %s", patch_result.c_str());
			}
		}
		catch (...)
		{
			warning("[PwnHelper] Patch failed: unexpected exception.");
		}
	}

	virtual size_t idaapi get_count() const override
	{
		return entries.size();
	}

	virtual void idaapi get_row(qstrvec_t* cols, int* icon_, chooser_item_attrs_t* attrs, size_t n) const override
	{
		if (cols == nullptr || n >= entries.size())
		{
			return;
		}

		if (cols->size() < 4)
		{
			cols->resize(4);
		}
		const VulnEntry& entry = entries[n];

		// ��ַ��
		qstring addr_str;
		addr_str.sprnt("%a", entry.address);
		cols->at(0) = addr_str;

		// ������
		cols->at(1) = entry.type;

		//������
		cols->at(2) = entry.description;


		if (entry.patch_suggestion.empty())
		{
			cols->at(3) = "N/A";
		}
		else
		{
			cols->at(3) = entry.patch_suggestion;
		}

		// ���ݷ��յȼ�����ͼ��
		if ( icon_)
		{
			if (entry.risk == RiskLevel::HIGH || entry.risk == RiskLevel::CRITICAL)
			{
				*icon_ = 5;
			}
			else if (entry.risk == RiskLevel::MEDIUM)
			{
				*icon_ = 4;
			}
			else
			{
				*icon_ = -1;
			}
		}

	}

	// ˫����ת
	virtual cbret_t idaapi enter(size_t n) override
	{
		if (n < entries.size())
		{
			const VulnEntry& entry = entries[n];
			jumpto(entry.address);
		}
		return cbret_t();
	}

	virtual cbret_t idaapi edit(size_t n) override
	{
		ApplyPatchForIndex(n);
		return cbret_t();
	}
};

class test_plugin_t : public plugmod_t
{
public:
	virtual bool idaapi run(size_t arg) override
	{
		// ʵ��������
		ScannerEngine engine;

		VulnChooser* chooser = new VulnChooser("Vuln Results");

		// ִ��ɨ��
		engine.ScanAll(chooser->entries);

		ea_t start_ea = get_name_ea(BADADDR, "_start");
		if (start_ea == BADADDR)
		{
			start_ea = get_name_ea(BADADDR, "start");
		}
		if (start_ea != BADADDR)
		{
			chooser->entries.emplace_back(
				start_ea,
				"Generic Defense",
				"Optional startup hardening: hook _start before __libc_start_main and apply prctl restrictions.",
				RiskLevel::MEDIUM,
				"Patch: install _start trampoline and apply default prctl hardening before handing off to __libc_start_main.",
				PatchAction::START_PRCTL_HARDEN);
		}

		if (chooser->entries.empty())
		{
			int resp = ask_yn(1, "No vulnerabilities found.\nDo you still want to open the empty list?");
			if (resp != 1)
			{
				delete chooser;
				return true;
			}
		}

		chooser->choose();

		return true;
	}
};

plugmod_t* idaapi init()
{
	if (!init_hexrays_plugin())
	{
		warning("Hex-Rays decompiler is required. Plugin will not be loaded.\n");
		return nullptr;
	}

	msg("VulnScanner UI plugin initialized.\n");
	return new test_plugin_t;
}

// �����Ϣ
plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,
	PLUGIN_MULTI,
	init,
	nullptr,
	nullptr,
	"VulnScanner UI",
	"Help",
	"VulnScanner",
	"Alt-F8"
};
