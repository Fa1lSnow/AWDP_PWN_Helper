#pragma once

#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <ua.hpp>
#include <funcs.hpp>

#include <vector>
#include <algorithm>
#include <cctype>
#include <unordered_map>

#include "VulnData.hpp"

class PatchEngine
{
public:
	static bool ResolveEntryStart(ea_t& out_ea, qstring* out_name = nullptr)
	{
		out_ea = BADADDR;

		const char* kCandidates[] = { "_start", "start", ".start", "__start" };
		for (const char* name : kCandidates)
		{
			ea_t ea = get_name_ea(BADADDR, name);
			if (ea != BADADDR)
			{
				out_ea = ea;
				if (out_name != nullptr)
				{
					*out_name = name;
				}
				return true;
			}
		}

		size_t qty = get_func_qty();
		for (size_t i = 0; i < qty; ++i)
		{
			func_t* f = getn_func(i);
			if (f == nullptr)
			{
				continue;
			}

			qstring fn;
			get_func_name(&fn, f->start_ea);
			if (fn.empty())
			{
				continue;
			}

			qstring norm = fn;
			while (!norm.empty() && (norm[0] == '_' || norm[0] == '.'))
			{
				norm.remove(0, 1);
			}
			for (size_t j = 0; j < norm.length(); ++j)
			{
				norm[j] = static_cast<char>(std::tolower(static_cast<unsigned char>(norm[j])));
			}
			if (norm == "start")
			{
				out_ea = f->start_ea;
				if (out_name != nullptr)
				{
					*out_name = fn;
				}
				return true;
			}
		}

		return false;
	}

	static bool ApplyDefaultStartPrctlMitigation(qstring& out_msg)
	{
		// _start 防护补丁流程：定位 __libc_start_main 调用点，
		// 在 frame 段写入 trampoline，先执行 prctl/seccomp，再回到原流程
		ea_t start_ea = BADADDR;
		qstring start_name;
		if (!ResolveEntryStart(start_ea, &start_name))
		{
			out_msg = "entry symbol not found (tried _start/start variants).";
			return false;
		}

		func_t* f = get_func(start_ea);
		if (f == nullptr)
		{
			out_msg.cat_sprnt("entry function metadata not found: %s.", start_name.c_str());
			return false;
		}

		ea_t call_ea = BADADDR;
		ea_t libc_ptr_slot = BADADDR;
		ea_t libc_call_target = BADADDR;
		size_t call_insn_size = 0;
		bool call_is_indirect = false;
		for (ea_t ea = f->start_ea; ea != BADADDR && ea < f->end_ea; ea = next_head(ea, f->end_ea))
		{
			insn_t insn;
			if (decode_insn(&insn, ea) <= 0)
			{
				continue;
			}

			qstring mnem;
			print_insn_mnem(&mnem, ea);
			if (mnem != "call")
			{
				continue;
			}

			qstring op0;
			print_operand(&op0, ea, 0);
			if (op0.find("libc_start_main") == qstring::npos)
			{
				continue;
			}

			if (insn.size == 6 && get_byte(ea) == 0xFF && get_byte(ea + 1) == 0x15)
			{
				int32 disp = static_cast<int32>(ReadU32(ea + 2));
				libc_ptr_slot = ea + 6 + disp;
				call_ea = ea;
				call_insn_size = insn.size;
				call_is_indirect = true;
				break;
			}

			if (insn.size == 5 && get_byte(ea) == 0xE8)
			{
				int32 disp = static_cast<int32>(ReadU32(ea + 1));
				libc_call_target = ea + 5 + disp;
				call_ea = ea;
				call_insn_size = insn.size;
				call_is_indirect = false;
				break;
			}
		}

		if (call_ea == BADADDR)
		{
			out_msg.cat_sprnt("__libc_start_main callsite not found in entry: %s.", start_name.c_str());
			return false;
		}

		if (call_is_indirect && libc_ptr_slot == BADADDR)
		{
			out_msg.cat_sprnt("__libc_start_main indirect slot not resolved in entry: %s.", start_name.c_str());
			return false;
		}

		if (!call_is_indirect && libc_call_target == BADADDR)
		{
			out_msg.cat_sprnt("__libc_start_main direct target not resolved in entry: %s.", start_name.c_str());
			return false;
		}

		bool repatching = (get_byte(call_ea) == 0xE9);

		ea_t ret_ea = call_ea + call_insn_size;
		if (!Is64Bit())
		{
			out_msg = "_start prctl mitigation currently supports x64 only.";
			return false;
		}

		std::vector<uint8> stub;
		auto emit = [&stub](std::initializer_list<uint8> bytes)
		{
			stub.insert(stub.end(), bytes.begin(), bytes.end());
		};

		emit({0x57,0x56,0x52,0x51,0x41,0x50,0x41,0x51});
		emit({0xB8,0x9D,0x00,0x00,0x00,0xBF,0x26,0x00,0x00,0x00,0xBE,0x01,0x00,0x00,0x00,0x31,0xD2,0x45,0x31,0xD2,0x45,0x31,0xC0,0x0F,0x05});
		emit({0x85,0xC0});
		size_t js_fail1_disp_pos = stub.size() + 1;
		emit({0x78,0x00});

		emit({0xB8,0x9D,0x00,0x00,0x00});
		emit({0xBF,0x16,0x00,0x00,0x00});
		emit({0xBE,0x02,0x00,0x00,0x00});
		emit({0x48,0x83,0xEC,0x10});
		emit({0xC7,0x44,0x24,0x04,0x00,0x00,0x00,0x00});
		emit({0x66,0xC7,0x44,0x24,0x02,0x00,0x00});
		emit({0x66,0xC7,0x04,0x24,0x0B,0x00});

		size_t lea_filter_disp_pos = stub.size() + 3;
		emit({0x48,0x8D,0x0D,0,0,0,0});
		emit({0x48,0x89,0x4C,0x24,0x08});
		emit({0x48,0x89,0xE2});
		emit({0x45,0x31,0xD2,0x45,0x31,0xC0,0x0F,0x05});
		emit({0x48,0x83,0xC4,0x10});

		size_t restore_regs_off = stub.size();
		emit({0x41,0x59,0x41,0x58,0x59,0x5A,0x5E,0x5F});
		size_t call_disp_pos = stub.size();
		if (call_is_indirect)
		{
			call_disp_pos = stub.size() + 2;
			emit({0xFF,0x15,0,0,0,0});
		}
		else
		{
			call_disp_pos = stub.size() + 1;
			emit({0xE8,0,0,0,0});
		}
		size_t jmp_back_disp_pos = stub.size() + 1;
		emit({0xE9,0,0,0,0});

		size_t filter_off = stub.size();
		emit({0x20,0x00,0x00,0x00,0x04,0x00,0x00,0x00});
		emit({0x15,0x00,0x01,0x00,0x3E,0x00,0x00,0xC0});
		emit({0x06,0x00,0x00,0x00,0x00,0x00,0x00,0x00});
		emit({0x20,0x00,0x00,0x00,0x00,0x00,0x00,0x00});
		emit({0x15,0x00,0x05,0x00,0x02,0x00,0x00,0x00});
		emit({0x15,0x00,0x04,0x00,0x01,0x01,0x00,0x00});
		emit({0x15,0x00,0x03,0x00,0x3B,0x00,0x00,0x00});
		emit({0x15,0x00,0x02,0x00,0x42,0x01,0x00,0x00});
		emit({0x15,0x00,0x01,0x00,0xB5,0x01,0x00,0x00});
		emit({0x06,0x00,0x00,0x00,0x00,0x00,0xFF,0x7F});
		emit({0x06,0x00,0x00,0x00,0x00,0x00,0x00,0x00});

		int64 rel_js_fail1 = static_cast<int64>(restore_regs_off) - static_cast<int64>(js_fail1_disp_pos + 1);
		if (rel_js_fail1 < INT8_MIN || rel_js_fail1 > INT8_MAX)
		{
			out_msg = "_start mitigation first prctl failure jump out of range.";
			return false;
		}
		stub[js_fail1_disp_pos] = static_cast<uint8>(rel_js_fail1 & 0xFF);

		// 仅允许写入 frame 系列段，避免破坏业务代码段布局
		const char* kCandidates[] = { ".eh_frame_hdr", ".eh_frame", ".frame.hdr", ".frame" };
		segment_t* chosen_seg = nullptr;
		qstring last_reason;
		for (const char* want : kCandidates)
		{
			for (segment_t* seg = get_first_seg(); seg != nullptr; seg = get_next_seg(seg->start_ea))
			{
				qstring seg_name;
				get_segm_name(&seg_name, seg);
				if (seg_name != want)
				{
					continue;
				}

				if ((seg->perm & SEGPERM_EXEC) == 0)
				{
					seg->perm |= SEGPERM_EXEC;
				}

				qstring elf_msg;
				if (!EnsureEhFrameExecInElfHeaders(seg->start_ea, elf_msg))
				{
					last_reason.cat_sprnt("%s: %s ", seg_name.c_str(), elf_msg.c_str());
					continue;
				}

				ea_t seg_size = seg->end_ea - seg->start_ea;
				if (seg_size < stub.size())
				{
					last_reason.cat_sprnt("%s too small (%llu < %llu). ",
						seg_name.c_str(),
						static_cast<unsigned long long>(seg_size),
						static_cast<unsigned long long>(stub.size()));
					continue;
				}

				chosen_seg = seg;
				break;
			}
			if (chosen_seg != nullptr)
			{
				break;
			}
		}

		if (chosen_seg == nullptr)
		{
			if (last_reason.empty())
			{
				out_msg = "No frame segment found for _start mitigation.";
			}
			else
			{
				out_msg.cat_sprnt("No suitable frame segment for _start mitigation. %s", last_reason.c_str());
			}
			return false;
		}

		ea_t cave = chosen_seg->start_ea;

		ea_t filter_ea = cave + filter_off;
		ea_t lea_filter_start = cave + (lea_filter_disp_pos - 3);
		int32 rel_filter = 0;
		if (!CalcRel32(lea_filter_start + 7, filter_ea, rel_filter))
		{
			out_msg = "_start mitigation filter lea out of range.";
			return false;
		}
		stub[lea_filter_disp_pos + 0] = static_cast<uint8>(rel_filter & 0xFF);
		stub[lea_filter_disp_pos + 1] = static_cast<uint8>((rel_filter >> 8) & 0xFF);
		stub[lea_filter_disp_pos + 2] = static_cast<uint8>((rel_filter >> 16) & 0xFF);
		stub[lea_filter_disp_pos + 3] = static_cast<uint8>((rel_filter >> 24) & 0xFF);

		int32 rel_call = 0;
		ea_t call_to = call_is_indirect ? libc_ptr_slot : libc_call_target;
		if (!CalcRel32(cave + (call_disp_pos + 4), call_to, rel_call))
		{
			out_msg = "_start mitigation libc_start_main call target out of range.";
			return false;
		}
		stub[call_disp_pos + 0] = static_cast<uint8>(rel_call & 0xFF);
		stub[call_disp_pos + 1] = static_cast<uint8>((rel_call >> 8) & 0xFF);
		stub[call_disp_pos + 2] = static_cast<uint8>((rel_call >> 16) & 0xFF);
		stub[call_disp_pos + 3] = static_cast<uint8>((rel_call >> 24) & 0xFF);

		int32 rel_ret = 0;
		if (!CalcRel32(cave + (jmp_back_disp_pos + 4), ret_ea, rel_ret))
		{
			out_msg = "_start mitigation return jump out of range.";
			return false;
		}
		stub[jmp_back_disp_pos + 0] = static_cast<uint8>(rel_ret & 0xFF);
		stub[jmp_back_disp_pos + 1] = static_cast<uint8>((rel_ret >> 8) & 0xFF);
		stub[jmp_back_disp_pos + 2] = static_cast<uint8>((rel_ret >> 16) & 0xFF);
		stub[jmp_back_disp_pos + 3] = static_cast<uint8>((rel_ret >> 24) & 0xFF);

		if (!EmitBytes(cave, stub, out_msg))
		{
			return false;
		}

		if (!PatchJmp(call_ea, cave, call_insn_size, out_msg))
		{
			return false;
		}

		set_cmt(call_ea, "PwnHelper generic hardening: prctl seccomp strict before __libc_start_main", true);
		if (repatching)
		{
			out_msg.cat_sprnt("Re-applied _start mitigation trampoline at %a.", cave);
		}
		else
		{
			out_msg.cat_sprnt("Applied default _start mitigation trampoline at %a.", cave);
		}
		return true;
	}

	static bool CanAutoPatch(const VulnEntry& entry)
	{
		return entry.patch_action != PatchAction::NONE;
	}

	static bool ApplyPatch(const VulnEntry& entry, qstring& out_msg)
	{
		if (entry.patch_action == PatchAction::NONE)
		{
			out_msg = "No auto patch strategy for this finding.";
			return false;
		}

		switch (entry.patch_action)
		{
		case PatchAction::START_PRCTL_HARDEN:
			return ApplyDefaultStartPrctlMitigation(out_msg);
		case PatchAction::NOP_CALL:
			return PatchCallWithNops(entry, out_msg);
		case PatchAction::CLAMP_SIZE_ARG:
			return PatchCallClampSizeArg(entry, out_msg);
		case PatchAction::FRAME_FMT_SAFE_CALL:
			return PatchFormatCallViaFrame(entry, out_msg);
		case PatchAction::FRAME_FREE_AND_CLEAR_SLOT:
			return PatchFreeAndClearSlotViaFrame(entry, out_msg);
		default:
			break;
		}

		out_msg = "Unsupported patch action.";
		return false;
	}

private:
	static bool WriteByte(ea_t ea, uint8 v)
	{
		if (patch_byte(ea, v))
		{
			return true;
		}
		put_bytes(ea, &v, 1);
		return true;
	}

	static bool WriteDword(ea_t ea, uint32 v)
	{
		if (patch_dword(ea, v))
		{
			return true;
		}
		put_bytes(ea, &v, sizeof(v));
		return true;
	}

	static uint16 ReadU16(ea_t ea)
	{
		return static_cast<uint16>(get_byte(ea)) | (static_cast<uint16>(get_byte(ea + 1)) << 8);
	}

	static uint32 ReadU32(ea_t ea)
	{
		return static_cast<uint32>(get_byte(ea))
			| (static_cast<uint32>(get_byte(ea + 1)) << 8)
			| (static_cast<uint32>(get_byte(ea + 2)) << 16)
			| (static_cast<uint32>(get_byte(ea + 3)) << 24);
	}

	static uint64 ReadU64(ea_t ea)
	{
		return static_cast<uint64>(ReadU32(ea)) | (static_cast<uint64>(ReadU32(ea + 4)) << 32);
	}

	static bool WriteU64(ea_t ea, uint64 v)
	{
		uint32 lo = static_cast<uint32>(v & 0xFFFFFFFFULL);
		uint32 hi = static_cast<uint32>((v >> 32) & 0xFFFFFFFFULL);
		return WriteDword(ea, lo) && WriteDword(ea + 4, hi);
	}

	static ea_t FindElfHeaderEa()
	{
		for (segment_t* seg = get_first_seg(); seg != nullptr; seg = get_next_seg(seg->start_ea))
		{
			ea_t begin = seg->start_ea;
			ea_t end = seg->end_ea;
			if (end <= begin)
			{
				continue;
			}

			ea_t scan_end = begin + 0x400;
			if (scan_end > end)
			{
				scan_end = end;
			}

			for (ea_t ea = begin; ea + 4 <= scan_end; ++ea)
			{
				if (get_byte(ea) == 0x7F && get_byte(ea + 1) == 'E' && get_byte(ea + 2) == 'L' && get_byte(ea + 3) == 'F')
				{
					return ea;
				}
			}
		}

		return BADADDR;
	}

	static bool EnsureEhFrameExecInElfHeaders(ea_t seg_start, qstring& out_msg)
	{
		ea_t eh = FindElfHeaderEa();
		if (eh == BADADDR)
		{
			out_msg = "ELF header not found in mapped database.";
			return false;
		}

		uint8 elf_class = get_byte(eh + 4);
		uint8 elf_data = get_byte(eh + 5);
		if (elf_data != 1)
		{
			out_msg = "Only little-endian ELF is supported for header patch.";
			return false;
		}

		uint64 e_phoff = 0;
		uint16 e_phentsize = 0;
		uint16 e_phnum = 0;
		uint64 e_shoff = 0;
		uint16 e_shentsize = 0;
		uint16 e_shnum = 0;
		uint16 e_shstrndx = 0;

		if (elf_class == 2)
		{
			e_phoff = ReadU64(eh + 0x20);
			e_shoff = ReadU64(eh + 0x28);
			e_phentsize = ReadU16(eh + 0x36);
			e_phnum = ReadU16(eh + 0x38);
			e_shentsize = ReadU16(eh + 0x3A);
			e_shnum = ReadU16(eh + 0x3C);
			e_shstrndx = ReadU16(eh + 0x3E);
		}
		else if (elf_class == 1)
		{
			e_phoff = ReadU32(eh + 0x1C);
			e_shoff = ReadU32(eh + 0x20);
			e_phentsize = ReadU16(eh + 0x2A);
			e_phnum = ReadU16(eh + 0x2C);
			e_shentsize = ReadU16(eh + 0x2E);
			e_shnum = ReadU16(eh + 0x30);
			e_shstrndx = ReadU16(eh + 0x32);
		}
		else
		{
			out_msg = "Unsupported ELF class.";
			return false;
		}

		bool patched_ph = false;
		for (uint16 i = 0; i < e_phnum; ++i)
		{
			ea_t ph = eh + e_phoff + static_cast<uint64>(i) * e_phentsize;
			if (elf_class == 2)
			{
				uint32 p_type = ReadU32(ph + 0x00);
				uint32 p_flags = ReadU32(ph + 0x04);
				uint64 p_vaddr = ReadU64(ph + 0x10);
				uint64 p_memsz = ReadU64(ph + 0x28);
				if (p_type == 1 && seg_start >= p_vaddr && seg_start < (p_vaddr + p_memsz))
				{
					if ((p_flags & 0x1) == 0)
					{
						WriteDword(ph + 0x04, p_flags | 0x1);
					}
					patched_ph = true;
				}
			}
			else
			{
				uint32 p_type = ReadU32(ph + 0x00);
				uint32 p_vaddr = ReadU32(ph + 0x08);
				uint32 p_memsz = ReadU32(ph + 0x14);
				uint32 p_flags = ReadU32(ph + 0x18);
				if (p_type == 1 && seg_start >= p_vaddr && seg_start < (static_cast<uint64>(p_vaddr) + p_memsz))
				{
					if ((p_flags & 0x1) == 0)
					{
						WriteDword(ph + 0x18, p_flags | 0x1);
					}
					patched_ph = true;
				}
			}
		}

		bool patched_sh = false;
		if (e_shoff != 0 && e_shnum != 0 && e_shstrndx < e_shnum)
		{
			ea_t shstr = eh + e_shoff + static_cast<uint64>(e_shstrndx) * e_shentsize;
			uint64 shstr_off = (elf_class == 2) ? ReadU64(shstr + 0x18) : ReadU32(shstr + 0x10);
			for (uint16 i = 0; i < e_shnum; ++i)
			{
				ea_t sh = eh + e_shoff + static_cast<uint64>(i) * e_shentsize;
				uint32 sh_name = ReadU32(sh + 0x00);
				ea_t name_ea = eh + shstr_off + sh_name;
				qstring sec_name;
				get_strlit_contents(&sec_name, name_ea, -1, STRTYPE_C);
				if (sec_name == ".eh_frame" || sec_name == ".eh_frame_hdr")
				{
					if (elf_class == 2)
					{
						uint64 sh_flags = ReadU64(sh + 0x08);
						if ((sh_flags & 0x4) == 0)
						{
							WriteU64(sh + 0x08, sh_flags | 0x4);
						}
					}
					else
					{
						uint32 sh_flags = ReadU32(sh + 0x08);
						if ((sh_flags & 0x4) == 0)
						{
							WriteDword(sh + 0x08, sh_flags | 0x4);
						}
					}
					patched_sh = true;
				}
			}
		}

		if (!patched_ph && !patched_sh)
		{
			out_msg = "ELF headers parsed, but matching .eh_frame load/section entry not found.";
			return false;
		}

		return true;
	}

	static bool Is64Bit()
	{
		return inf_is_64bit();
	}

	static bool DecodeCallInsn(ea_t ea, insn_t& out_insn, ea_t& out_target, qstring& out_msg)
	{
		if (ea == BADADDR || !is_mapped(ea))
		{
			out_msg = "Invalid or unmapped patch address.";
			return false;
		}

		int decoded = decode_insn(&out_insn, ea);
		if (decoded <= 0 || out_insn.size == 0)
		{
			out_msg = "Failed to decode instruction at vulnerability address.";
			return false;
		}

		qstring mnem;
		print_insn_mnem(&mnem, ea);
		if (mnem != "call")
		{
			out_msg.cat_sprnt("Safety check failed: instruction at %a is not a call (%s).", ea, mnem.c_str());
			return false;
		}

		if (out_insn.Op1.type != o_near && out_insn.Op1.type != o_far)
		{
			out_msg = "Only direct call patching is supported.";
			return false;
		}

		out_target = out_insn.Op1.addr;
		if (out_target == BADADDR)
		{
			out_msg = "Failed to resolve call target.";
			return false;
		}

		return true;
	}

	static bool CalcRel32(ea_t src_next, ea_t dst, int32& rel)
	{
		int64 delta = static_cast<int64>(dst) - static_cast<int64>(src_next);
		if (delta < INT32_MIN || delta > INT32_MAX)
		{
			return false;
		}
		rel = static_cast<int32>(delta);
		return true;
	}

	static bool PatchJmp(ea_t from, ea_t to, size_t overwrite_size, qstring& out_msg)
	{
		if (overwrite_size < 5)
		{
			out_msg = "Instruction too small for JMP trampoline patch.";
			return false;
		}

		int32 rel = 0;
		if (!CalcRel32(from + 5, to, rel))
		{
			out_msg = "Relative JMP out of range.";
			return false;
		}

		if (!WriteByte(from, 0xE9))
		{
			out_msg.cat_sprnt("Failed to patch JMP opcode at %a.", from);
			return false;
		}
		if (!WriteDword(from + 1, static_cast<uint32>(rel)))
		{
			out_msg.cat_sprnt("Failed to patch JMP displacement at %a.", from + 1);
			return false;
		}

		for (size_t i = 5; i < overwrite_size; ++i)
		{
			if (!WriteByte(from + i, 0x90))
			{
				out_msg.cat_sprnt("Failed to patch NOP at %a.", from + i);
				return false;
			}
		}

		return true;
	}

	static bool EnsureFrameExec(segment_t*& out_seg, qstring& out_msg)
	{
		out_seg = nullptr;
		const char* kCandidates[] = { ".frame.hdr", ".frame", ".eh_frame_hdr", ".eh_frame" };
		for (const char* want : kCandidates)
		{
			for (segment_t* seg = get_first_seg(); seg != nullptr; seg = get_next_seg(seg->start_ea))
			{
				qstring seg_name;
				get_segm_name(&seg_name, seg);
				if (seg_name == want)
				{
					out_seg = seg;
					break;
				}
			}
			if (out_seg != nullptr)
			{
				break;
			}
		}

		if (out_seg == nullptr)
		{
			out_msg = "No patch segment found (.frame.hdr/.frame/.eh_frame_hdr/.eh_frame).";
			return false;
		}

		if ((out_seg->perm & SEGPERM_EXEC) == 0)
		{
			out_seg->perm |= SEGPERM_EXEC;
		}

		qstring elf_msg;
		if (!EnsureEhFrameExecInElfHeaders(out_seg->start_ea, elf_msg))
		{
			out_msg.cat_sprnt("%s", elf_msg.c_str());
			return false;
		}

		return true;
	}

	static ea_t FindCodeCave(segment_t* seg, size_t need)
	{
		// 优先搜索连续 0x00/0xCC 区域；找不到时回退到可映射区域
		// 该策略在不同装载器产物上更稳健，但可能覆盖无意义填充字节
		if (seg == nullptr || need == 0 || seg->end_ea <= seg->start_ea || seg->end_ea - seg->start_ea < need)
		{
			return BADADDR;
		}

		static std::unordered_map<ea_t, ea_t> s_cave_cursor;
		ea_t lower = seg->start_ea;
		ea_t upper = seg->end_ea - need;
		auto it_cursor = s_cave_cursor.find(seg->start_ea);
		if (it_cursor == s_cave_cursor.end())
		{
			s_cave_cursor[seg->start_ea] = upper;
		}
		else
		{
			if (it_cursor->second < upper)
			{
				upper = it_cursor->second;
			}
		}

		if (upper < lower)
		{
			return BADADDR;
		}

		for (ea_t ea = lower; ea <= upper; ++ea)
		{
			bool ok = true;
			for (size_t i = 0; i < need; ++i)
			{
				if (!is_mapped(ea + i))
				{
					ok = false;
					break;
				}

				uint8 b = get_byte(ea + i);
				if (b != 0x00 && b != 0xCC)
				{
					ok = false;
					break;
				}
			}

			if (ok)
			{
				s_cave_cursor[seg->start_ea] = (ea > lower + need ? ea - need : lower);
				return ea;
			}
		}


		for (ea_t ea = upper; ea >= lower; --ea)
		{
			bool mapped = true;
			for (size_t i = 0; i < need; ++i)
			{
				if (!is_mapped(ea + i))
				{
					mapped = false;
					break;
				}
			}
			if (mapped)
			{
				s_cave_cursor[seg->start_ea] = (ea > lower + need ? ea - need : lower);
				return ea;
			}

			if (ea == lower)
			{
				break;
			}
		}

		return BADADDR;
	}

	static bool EmitBytes(ea_t at, const std::vector<uint8>& data, qstring& out_msg)
	{
		for (size_t i = 0; i < data.size(); ++i)
		{
			if (!WriteByte(at + i, data[i]))
			{
				out_msg.cat_sprnt("Failed to write stub byte at %a.", at + i);
				return false;
			}
		}
		return true;
	}

	static uint8 GetRegMovImmOpcode(int aux)
	{
		if (aux == 2)
		{
			return 0xBA;
		}
		if (aux == 1)
		{
			return 0xBE;
		}
		return 0;
	}

	static bool MatchRegToken(const qstring& token, int aux)
	{
		std::string t = token.c_str();
		t.erase(std::remove_if(t.begin(), t.end(), [](unsigned char c) { return std::isspace(c) != 0; }), t.end());
		std::transform(t.begin(), t.end(), t.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

		if (aux == 2)
		{
			return t == "edx" || t == "rdx";
		}
		if (aux == 1)
		{
			return t == "esi" || t == "rsi";
		}
		return false;
	}

	static bool PatchArgSetupInline(ea_t call_ea, int aux, uint32 clamp, qstring& out_msg)
	{
		uint8 opcode = GetRegMovImmOpcode(aux);
		if (opcode == 0)
		{
			out_msg = "Unsupported inline arg register selector.";
			return false;
		}

		ea_t lower = (call_ea > 0x80 ? call_ea - 0x80 : 0);
		ea_t cur = prev_head(call_ea, lower);
		for (int steps = 0; cur != BADADDR && cur < call_ea && steps < 20; ++steps)
		{
			insn_t insn;
			if (decode_insn(&insn, cur) > 0)
			{
				qstring mnem;
				print_insn_mnem(&mnem, cur);
				if (mnem == "mov")
				{
					qstring op0;
					print_operand(&op0, cur, 0);
					if (MatchRegToken(op0, aux) && insn.size >= 5)
					{
						if (!WriteByte(cur, opcode))
						{
							out_msg.cat_sprnt("Inline patch failed at %a.", cur);
							return false;
						}
						if (!WriteDword(cur + 1, clamp))
						{
							out_msg.cat_sprnt("Inline patch immediate failed at %a.", cur + 1);
							return false;
						}
						for (size_t i = 5; i < insn.size; ++i)
						{
							if (!WriteByte(cur + i, 0x90))
							{
								out_msg.cat_sprnt("Inline patch NOP failed at %a.", cur + i);
								return false;
							}
						}

						out_msg.cat_sprnt("Inline arg clamp patched at %a (value=%u).", cur, clamp);
						return true;
					}
				}
			}

			if (cur == lower)
			{
				break;
			}
			cur = prev_head(cur, lower);
		}

		out_msg = "No inline mov-arg setup found before call.";
		return false;
	}

	static bool PatchCallWithFrameStub(const VulnEntry& entry, const std::vector<uint8>& stub, qstring& out_msg)
	{
		insn_t call_insn;
		ea_t call_target = BADADDR;
		if (!DecodeCallInsn(entry.address, call_insn, call_target, out_msg))
		{
			return false;
		}

		segment_t* frame_seg = nullptr;
		if (!EnsureFrameExec(frame_seg, out_msg))
		{
			return false;
		}

		ea_t cave = FindCodeCave(frame_seg, stub.size());
		if (cave == BADADDR)
		{
			out_msg = "No executable code cave found in patch segment (.eh_frame_hdr/.eh_frame).";
			return false;
		}

		if (!EmitBytes(cave, stub, out_msg))
		{
			return false;
		}

		if (!PatchJmp(entry.address, cave, call_insn.size, out_msg))
		{
			return false;
		}

		if (!entry.patch_suggestion.empty())
		{
			set_cmt(entry.address, entry.patch_suggestion.c_str(), true);
		}

		out_msg.cat_sprnt("Patched call at %a via patch-segment trampoline %a.", entry.address, cave);
		return true;
	}

	static bool PatchCallClampSizeArg(const VulnEntry& entry, qstring& out_msg)
	{
		if (!Is64Bit())
		{
			out_msg = "CLAMP_SIZE_ARG currently supports only x64 binaries.";
			return false;
		}

		insn_t call_insn;
		ea_t call_target = BADADDR;
		if (!DecodeCallInsn(entry.address, call_insn, call_target, out_msg))
		{
			return false;
		}

		ea_t ret_ea = entry.address + call_insn.size;
		uint32 clamp = static_cast<uint32>(entry.patch_value > UINT32_MAX ? UINT32_MAX : entry.patch_value);

		// 先尝试就地改写“参数装载指令”，失败后再走 trampoline，
		// 这样能最小化控制流改动并保留更多原始语义
		qstring inline_result;
		if (PatchArgSetupInline(entry.address, entry.patch_aux, clamp, inline_result))
		{
			if (!entry.patch_suggestion.empty())
			{
				set_cmt(entry.address, entry.patch_suggestion.c_str(), true);
			}
			out_msg = inline_result;
			return true;
		}

		segment_t* frame_seg = nullptr;
		if (!EnsureFrameExec(frame_seg, out_msg))
		{
			return false;
		}

		std::vector<uint8> stub;

		if (entry.patch_aux == 2)
		{
			stub.push_back(0xBA);
		}
		else if (entry.patch_aux == 1)
		{
			stub.push_back(0xBE);
		}
		else
		{
			out_msg = "Unsupported CLAMP_SIZE_ARG register selector.";
			return false;
		}

		stub.push_back(static_cast<uint8>(clamp & 0xFF));
		stub.push_back(static_cast<uint8>((clamp >> 8) & 0xFF));
		stub.push_back(static_cast<uint8>((clamp >> 16) & 0xFF));
		stub.push_back(static_cast<uint8>((clamp >> 24) & 0xFF));

		size_t call_rel_off = stub.size();
		stub.push_back(0xE8);
		stub.insert(stub.end(), 4, 0x00);

		size_t jmp_rel_off = stub.size();
		stub.push_back(0xE9);
		stub.insert(stub.end(), 4, 0x00);

		ea_t cave = FindCodeCave(frame_seg, stub.size());
		if (cave == BADADDR)
		{
			out_msg = "No executable code cave found in patch segment (.eh_frame_hdr/.eh_frame).";
			return false;
		}

		int32 rel_call = 0;
		if (!CalcRel32(cave + call_rel_off + 5, call_target, rel_call))
		{
			out_msg = "Trampoline call target out of range.";
			return false;
		}
		stub[call_rel_off + 1] = static_cast<uint8>(rel_call & 0xFF);
		stub[call_rel_off + 2] = static_cast<uint8>((rel_call >> 8) & 0xFF);
		stub[call_rel_off + 3] = static_cast<uint8>((rel_call >> 16) & 0xFF);
		stub[call_rel_off + 4] = static_cast<uint8>((rel_call >> 24) & 0xFF);

		int32 rel_jmp = 0;
		if (!CalcRel32(cave + jmp_rel_off + 5, ret_ea, rel_jmp))
		{
			out_msg = "Trampoline return jump out of range.";
			return false;
		}
		stub[jmp_rel_off + 1] = static_cast<uint8>(rel_jmp & 0xFF);
		stub[jmp_rel_off + 2] = static_cast<uint8>((rel_jmp >> 8) & 0xFF);
		stub[jmp_rel_off + 3] = static_cast<uint8>((rel_jmp >> 16) & 0xFF);
		stub[jmp_rel_off + 4] = static_cast<uint8>((rel_jmp >> 24) & 0xFF);

		if (!EmitBytes(cave, stub, out_msg))
		{
			return false;
		}

		if (!PatchJmp(entry.address, cave, call_insn.size, out_msg))
		{
			return false;
		}

		if (!entry.patch_suggestion.empty())
		{
			set_cmt(entry.address, entry.patch_suggestion.c_str(), true);
		}

		out_msg.cat_sprnt("Clamped size arg to %u via patch-segment trampoline at %a.", clamp, cave);
		return true;
	}

	static bool PatchFormatCallViaFrame(const VulnEntry& entry, qstring& out_msg)
	{
		if (!Is64Bit())
		{
			out_msg = "FRAME_FMT_SAFE_CALL currently supports only x64 binaries.";
			return false;
		}

		insn_t call_insn;
		ea_t call_target = BADADDR;
		if (!DecodeCallInsn(entry.address, call_insn, call_target, out_msg))
		{
			return false;
		}

		ea_t ret_ea = entry.address + call_insn.size;
		segment_t* frame_seg = nullptr;
		if (!EnsureFrameExec(frame_seg, out_msg))
		{
			return false;
		}

		// 桩逻辑：把原格式参数移到 RSI，并将 RDI 改为 "%s"，
		// 然后调用原函数，实现“非字面量格式串”降级为安全打印
		std::vector<uint8> stub = {
			0x48, 0x89, 0xFE,
			0x48, 0x8D, 0x3D, 0x00, 0x00, 0x00, 0x00,
			0xE8, 0x00, 0x00, 0x00, 0x00,
			0xE9, 0x00, 0x00, 0x00, 0x00,
			0x25, 0x73, 0x00
		};

		ea_t cave = FindCodeCave(frame_seg, stub.size());
		if (cave == BADADDR)
		{
			out_msg = "No executable code cave found in patch segment (.eh_frame_hdr/.eh_frame).";
			return false;
		}

		ea_t fmt_ea = cave + 20;
		int32 rel_lea = 0;
		if (!CalcRel32(cave + 10, fmt_ea, rel_lea))
		{
			out_msg = "LEA RIP-relative displacement out of range.";
			return false;
		}
		stub[6] = static_cast<uint8>(rel_lea & 0xFF);
		stub[7] = static_cast<uint8>((rel_lea >> 8) & 0xFF);
		stub[8] = static_cast<uint8>((rel_lea >> 16) & 0xFF);
		stub[9] = static_cast<uint8>((rel_lea >> 24) & 0xFF);

		int32 rel_call = 0;
		if (!CalcRel32(cave + 15, call_target, rel_call))
		{
			out_msg = "Trampoline call target out of range.";
			return false;
		}
		stub[11] = static_cast<uint8>(rel_call & 0xFF);
		stub[12] = static_cast<uint8>((rel_call >> 8) & 0xFF);
		stub[13] = static_cast<uint8>((rel_call >> 16) & 0xFF);
		stub[14] = static_cast<uint8>((rel_call >> 24) & 0xFF);

		int32 rel_jmp = 0;
		if (!CalcRel32(cave + 20, ret_ea, rel_jmp))
		{
			out_msg = "Trampoline return jump out of range.";
			return false;
		}
		stub[16] = static_cast<uint8>(rel_jmp & 0xFF);
		stub[17] = static_cast<uint8>((rel_jmp >> 8) & 0xFF);
		stub[18] = static_cast<uint8>((rel_jmp >> 16) & 0xFF);
		stub[19] = static_cast<uint8>((rel_jmp >> 24) & 0xFF);

		if (!EmitBytes(cave, stub, out_msg))
		{
			return false;
		}

		if (!PatchJmp(entry.address, cave, call_insn.size, out_msg))
		{
			return false;
		}

		if (!entry.patch_suggestion.empty())
		{
			set_cmt(entry.address, entry.patch_suggestion.c_str(), true);
		}

		out_msg.cat_sprnt("Patched format call via patch-segment safe %%s trampoline at %a.", cave);
		return true;
	}

	static bool PatchFreeAndClearSlotViaFrame(const VulnEntry& entry, qstring& out_msg)
	{
		if (entry.patch_value == 0 || entry.patch_value == BADADDR)
		{
			out_msg = "Unresolved slot address for dangling-pointer patch.";
			return false;
		}

		insn_t call_insn;
		ea_t call_target = BADADDR;
		if (!DecodeCallInsn(entry.address, call_insn, call_target, out_msg))
		{
			return false;
		}

		ea_t ret_ea = entry.address + call_insn.size;
		segment_t* frame_seg = nullptr;
		if (!EnsureFrameExec(frame_seg, out_msg))
		{
			return false;
		}

		std::vector<uint8> stub;
		ea_t slot_ea = static_cast<ea_t>(entry.patch_value);

		// patch_aux==1 表示动态索引槽位（如 notes[idx]），需要在桩里重算目标地址
		if (entry.patch_aux == 1)
		{
			ea_t low = (entry.address > 0x80 ? entry.address - 0x80 : 0);
			ea_t cur = prev_head(entry.address, low);
			int idx_disp = 0;
			bool got_disp = false;
			for (int steps = 0; cur != BADADDR && cur < entry.address && steps < 16; ++steps)
			{
				insn_t insn;
				if (decode_insn(&insn, cur) > 0)
				{
					qstring mnem;
					print_insn_mnem(&mnem, cur);
					if (mnem == "mov" && insn.Op1.type == o_reg && insn.Op2.type == o_displ)
					{
						idx_disp = static_cast<int>(insn.Op2.addr);
						got_disp = true;
						break;
					}
				}
				if (cur == low)
				{
					break;
				}
				cur = prev_head(cur, low);
			}

			if (!got_disp)
			{
				out_msg = "Dynamic-index slot source not found near free call.";
				return false;
			}

			uint32 disp32 = static_cast<uint32>(idx_disp);
			ea_t cave = BADADDR;

			if (Is64Bit())
			{
				stub = {
					0xE8, 0x00, 0x00, 0x00, 0x00,
					0x8B, 0x85, 0, 0, 0, 0,
					0x48, 0x98,
					0x48, 0x8D, 0x0D, 0, 0, 0, 0,
					0x48, 0xC7, 0x04, 0xC1, 0x00, 0x00, 0x00, 0x00,
					0xE9, 0x00, 0x00, 0x00, 0x00
				};

				stub[7] = static_cast<uint8>(disp32 & 0xFF);
				stub[8] = static_cast<uint8>((disp32 >> 8) & 0xFF);
				stub[9] = static_cast<uint8>((disp32 >> 16) & 0xFF);
				stub[10] = static_cast<uint8>((disp32 >> 24) & 0xFF);

				cave = FindCodeCave(frame_seg, stub.size());
				if (cave == BADADDR)
				{
					out_msg = "No executable code cave found in patch segment (.eh_frame_hdr/.eh_frame).";
					return false;
				}

				int32 rel_slot64 = 0;
				if (!CalcRel32(cave + 20, slot_ea, rel_slot64))
				{
					out_msg = "RIP-relative slot displacement out of range.";
					return false;
				}
				stub[16] = static_cast<uint8>(rel_slot64 & 0xFF);
				stub[17] = static_cast<uint8>((rel_slot64 >> 8) & 0xFF);
				stub[18] = static_cast<uint8>((rel_slot64 >> 16) & 0xFF);
				stub[19] = static_cast<uint8>((rel_slot64 >> 24) & 0xFF);

				int32 rel_call_dyn = 0;
				if (!CalcRel32(cave + 5, call_target, rel_call_dyn))
				{
					out_msg = "Trampoline call target out of range.";
					return false;
				}
				stub[1] = static_cast<uint8>(rel_call_dyn & 0xFF);
				stub[2] = static_cast<uint8>((rel_call_dyn >> 8) & 0xFF);
				stub[3] = static_cast<uint8>((rel_call_dyn >> 16) & 0xFF);
				stub[4] = static_cast<uint8>((rel_call_dyn >> 24) & 0xFF);

				int32 rel_jmp_dyn = 0;
				if (!CalcRel32(cave + 33, ret_ea, rel_jmp_dyn))
				{
					out_msg = "Trampoline return jump out of range.";
					return false;
				}
				stub[29] = static_cast<uint8>(rel_jmp_dyn & 0xFF);
				stub[30] = static_cast<uint8>((rel_jmp_dyn >> 8) & 0xFF);
				stub[31] = static_cast<uint8>((rel_jmp_dyn >> 16) & 0xFF);
				stub[32] = static_cast<uint8>((rel_jmp_dyn >> 24) & 0xFF);
			}
			else
			{
				stub = {
					0xE8, 0x00, 0x00, 0x00, 0x00,
					0x8B, 0x8D, 0, 0, 0, 0,
					0xB8, 0, 0, 0, 0,
					0xC7, 0x04, 0x88, 0x00, 0x00, 0x00, 0x00,
					0xE9, 0x00, 0x00, 0x00, 0x00
				};

				stub[7] = static_cast<uint8>(disp32 & 0xFF);
				stub[8] = static_cast<uint8>((disp32 >> 8) & 0xFF);
				stub[9] = static_cast<uint8>((disp32 >> 16) & 0xFF);
				stub[10] = static_cast<uint8>((disp32 >> 24) & 0xFF);

				uint32 base32 = static_cast<uint32>(slot_ea & 0xFFFFFFFFULL);
				stub[12] = static_cast<uint8>(base32 & 0xFF);
				stub[13] = static_cast<uint8>((base32 >> 8) & 0xFF);
				stub[14] = static_cast<uint8>((base32 >> 16) & 0xFF);
				stub[15] = static_cast<uint8>((base32 >> 24) & 0xFF);

				cave = FindCodeCave(frame_seg, stub.size());
				if (cave == BADADDR)
				{
					out_msg = "No executable code cave found in patch segment (.eh_frame_hdr/.eh_frame).";
					return false;
				}

				int32 rel_call_dyn = 0;
				if (!CalcRel32(cave + 5, call_target, rel_call_dyn))
				{
					out_msg = "Trampoline call target out of range.";
					return false;
				}
				stub[1] = static_cast<uint8>(rel_call_dyn & 0xFF);
				stub[2] = static_cast<uint8>((rel_call_dyn >> 8) & 0xFF);
				stub[3] = static_cast<uint8>((rel_call_dyn >> 16) & 0xFF);
				stub[4] = static_cast<uint8>((rel_call_dyn >> 24) & 0xFF);

				int32 rel_jmp_dyn = 0;
				if (!CalcRel32(cave + 28, ret_ea, rel_jmp_dyn))
				{
					out_msg = "Trampoline return jump out of range.";
					return false;
				}
				stub[24] = static_cast<uint8>(rel_jmp_dyn & 0xFF);
				stub[25] = static_cast<uint8>((rel_jmp_dyn >> 8) & 0xFF);
				stub[26] = static_cast<uint8>((rel_jmp_dyn >> 16) & 0xFF);
				stub[27] = static_cast<uint8>((rel_jmp_dyn >> 24) & 0xFF);
			}

			if (!EmitBytes(cave, stub, out_msg))
			{
				return false;
			}

			if (!PatchJmp(entry.address, cave, call_insn.size, out_msg))
			{
				return false;
			}

			if (!entry.patch_suggestion.empty())
			{
				set_cmt(entry.address, entry.patch_suggestion.c_str(), true);
			}

			out_msg.cat_sprnt("Patched dynamic-index free call and cleared slot base %a with stack-index recompute.", slot_ea);
			return true;
		}

		if (Is64Bit())
		{
			stub = {
				0xE8, 0x00, 0x00, 0x00, 0x00,
				0x48, 0x8D, 0x05, 0, 0, 0, 0,
				0x48, 0xC7, 0x00, 0x00, 0x00, 0x00, 0x00,
				0xE9, 0x00, 0x00, 0x00, 0x00
			};
		}
		else
		{
			stub = {
				0xE8, 0x00, 0x00, 0x00, 0x00,
				0xB8, 0x00, 0x00, 0x00, 0x00,
				0xC7, 0x00, 0x00, 0x00, 0x00, 0x00,
				0xE9, 0x00, 0x00, 0x00, 0x00
			};
		}

		ea_t cave = FindCodeCave(frame_seg, stub.size());
		if (cave == BADADDR)
		{
			out_msg = "No executable code cave found in patch segment (.eh_frame_hdr/.eh_frame).";
			return false;
		}

		size_t call_rel_off = 0;
		size_t jmp_rel_off = Is64Bit() ? 19 : 16;

		int32 rel_call = 0;
		if (!CalcRel32(cave + call_rel_off + 5, call_target, rel_call))
		{
			out_msg = "Trampoline call target out of range.";
			return false;
		}
		stub[call_rel_off + 1] = static_cast<uint8>(rel_call & 0xFF);
		stub[call_rel_off + 2] = static_cast<uint8>((rel_call >> 8) & 0xFF);
		stub[call_rel_off + 3] = static_cast<uint8>((rel_call >> 16) & 0xFF);
		stub[call_rel_off + 4] = static_cast<uint8>((rel_call >> 24) & 0xFF);

		if (Is64Bit())
		{
			int32 rel_slot = 0;
			if (!CalcRel32(cave + 12, slot_ea, rel_slot))
			{
				out_msg = "RIP-relative slot displacement out of range.";
				return false;
			}
			stub[8] = static_cast<uint8>(rel_slot & 0xFF);
			stub[9] = static_cast<uint8>((rel_slot >> 8) & 0xFF);
			stub[10] = static_cast<uint8>((rel_slot >> 16) & 0xFF);
			stub[11] = static_cast<uint8>((rel_slot >> 24) & 0xFF);
		}
		else
		{
			uint32 addr32 = static_cast<uint32>(slot_ea & 0xFFFFFFFFULL);
			stub[6] = static_cast<uint8>(addr32 & 0xFF);
			stub[7] = static_cast<uint8>((addr32 >> 8) & 0xFF);
			stub[8] = static_cast<uint8>((addr32 >> 16) & 0xFF);
			stub[9] = static_cast<uint8>((addr32 >> 24) & 0xFF);
		}

		int32 rel_jmp = 0;
		if (!CalcRel32(cave + jmp_rel_off + 5, ret_ea, rel_jmp))
		{
			out_msg = "Trampoline return jump out of range.";
			return false;
		}
		stub[jmp_rel_off + 1] = static_cast<uint8>(rel_jmp & 0xFF);
		stub[jmp_rel_off + 2] = static_cast<uint8>((rel_jmp >> 8) & 0xFF);
		stub[jmp_rel_off + 3] = static_cast<uint8>((rel_jmp >> 16) & 0xFF);
		stub[jmp_rel_off + 4] = static_cast<uint8>((rel_jmp >> 24) & 0xFF);

		if (!EmitBytes(cave, stub, out_msg))
		{
			return false;
		}

		if (!PatchJmp(entry.address, cave, call_insn.size, out_msg))
		{
			return false;
		}

		if (!entry.patch_suggestion.empty())
		{
			set_cmt(entry.address, entry.patch_suggestion.c_str(), true);
		}

		out_msg.cat_sprnt("Patched free call via trampoline and cleared slot %a.", slot_ea);
		return true;
	}

	static bool PatchCallWithNops(const VulnEntry& entry, qstring& out_msg)
	{
		insn_t insn;
		ea_t ignored_target = BADADDR;
		if (!DecodeCallInsn(entry.address, insn, ignored_target, out_msg))
		{
			return false;
		}

		if (insn.size > 16)
		{
			out_msg = "Safety check failed: target instruction is too large for automatic NOP patch.";
			return false;
		}

		for (size_t i = 0; i < insn.size; ++i)
		{
			if (!WriteByte(entry.address + i, 0x90))
			{
				out_msg.cat_sprnt("Patch failed at %a.", entry.address + i);
				return false;
			}
		}

		if (!entry.patch_suggestion.empty())
		{
			set_cmt(entry.address, entry.patch_suggestion.c_str(), true);
		}

		out_msg.cat_sprnt("Patched %u byte(s) at %a with NOPs.", static_cast<unsigned>(insn.size), entry.address);
		return true;
	}
};
