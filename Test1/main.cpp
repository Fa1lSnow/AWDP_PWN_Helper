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
 * 定义UI窗口类
 */
class VulnChooser : public chooser_t
{
public:
	// 漏洞数据列表
	VulnList entries;

public:
	VulnChooser( const char* title)
		: chooser_t(0, 3, new int[3] {15, 20, 60}, new const char* [3] {"Address", "Type", "Description"}, title)
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

		// 地址列
		qstring addr_str;
		addr_str.sprnt("%a", entry.address);
		cols->at(0) = addr_str;

		// 类型列
		cols->at(1) = entry.type;

		//描述列
		cols->at(2) = entry.description;


		// 根据风险等级设置图标
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

	// 双击跳转
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

		// 实例化引擎
		ScannerEngine engine;

		// 必须 new 一个对象，否则 run 结束之后 chooser 会被析构
		VulnChooser* chooser = new VulnChooser("Vuln Results");

		// 执行扫描
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
	msg("VulnScanner UI plugin initialized.\n");
	return new test_plugin_t;
}

// 插件信息
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
