#define __EA64__

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <vector>
#include <string>

#include "VulnData.hpp"
#include "ScannerEngine.hpp"

/**
 * ����UI������
 */
class VulnChooser : public chooser_t
{
public:
	static constexpr int kColumnWidths[3] = {15, 20, 60};
	static constexpr const char* kColumnHeaders[3] = {"Address", "Type", "Description"};

	// ©�������б�
	VulnList entries;

public:
	VulnChooser( const char* title)
		: chooser_t(0, 3, kColumnWidths, kColumnHeaders, title)
	{
	}

	virtual size_t idaapi get_count() const override
	{
		return entries.size();
	}

	virtual void idaapi get_row(qstrvec_t* cols, int* icon_, chooser_item_attrs_t* attrs, size_t n) const override
	{
		if (n >= entries.size())
		{
			return;
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
			jumpto(entries[n].address);
		}
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
