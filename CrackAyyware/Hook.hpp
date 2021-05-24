//=====================================================================================

#pragma once

#include <Windows.h>
#include <vector>

//=====================================================================================

enum x86Instruction : BYTE { CALL = 0xE8, JMP };

//=====================================================================================

union Ptr
{
	void*  void_ptr;
	void** void_double_ptr;

	BYTE*  byte_ptr;
	WORD*  word_ptr;
	DWORD* dword_ptr;
};

//=====================================================================================

class Hook
{
public:
	Hook(x86Instruction instruction, void* address, void* target_function, unsigned int nops = 0, bool unhook_in_dtor = false) :
		instruction{ instruction },
		address{ address },
		target_function{ target_function },
		nops{ nops },
		unhook_in_dtor{ unhook_in_dtor },
		hooked{ false }
	{

	}

	~Hook()
	{
		if (unhook_in_dtor && hooked)
		{
			try
			{
				UnHook();
			}
			catch (...)
			{

			}
		}
	}

	void SetHook()
	{
		DWORD old_protection{ 0 };

		VirtualProtect(address.void_ptr, 5 + nops, PAGE_EXECUTE_READWRITE, &old_protection);

		for (unsigned int i = 0; i < 5 + nops; ++i)
		{
			old_bytes.push_back(address.byte_ptr[i]);
		}

		*address.byte_ptr = instruction;

		DWORD call_bytes{ static_cast<DWORD>(target_function.byte_ptr - (address.byte_ptr + 5)) };

		*reinterpret_cast<DWORD*>(address.byte_ptr + 1) = call_bytes;

		for (unsigned int i = 5; i < (5 + nops); ++i)
		{
			address.byte_ptr[i] = 0x90;
		}

		hooked = true;

		VirtualProtect(address.void_ptr, 5 + nops, DWORD(old_protection), &old_protection);
	}

	void UnHook()
	{
		DWORD old_protection{ 0 };

		VirtualProtect(address.void_ptr, 5 + nops, PAGE_EXECUTE_READWRITE, &old_protection);

		for (unsigned int i = 0; i < 5 + nops; ++i)
		{
			address.byte_ptr[i] = old_bytes[i];
		}

		hooked = false;

		VirtualProtect(address.void_ptr, 5 + nops, DWORD(old_protection), &old_protection);
	}

	bool IsHooked() const
	{
		return hooked;
	}

private:
	x86Instruction	  instruction;
	Ptr				  address;
	Ptr				  target_function;
	unsigned int	  nops;
	bool			  unhook_in_dtor;
	bool			  hooked;
	std::vector<BYTE> old_bytes;

	Hook() = delete;
	Hook(const Hook& other) = delete;
	Hook(Hook&& other) = delete;

	Hook& operator=(const Hook& other) = delete;
	Hook& operator=(Hook&& other) = delete;
};

//=====================================================================================

class HotPatch
{
public:
	HotPatch(void* function, void* new_function, bool unpatch_in_dtor = false) :
		function{ function },
		new_function{ new_function },
		unpatch_in_dtor{ unpatch_in_dtor },
		patched{ false }
	{

	}

	~HotPatch()
	{
		if (unpatch_in_dtor && patched)
		{
			try
			{
				UnPatch();
			}
			catch (...)
			{

			}
		}
	}

	void* Patch()
	{
		void* original_function = nullptr;

		DWORD protection{ 0 };

		hotpatch = reinterpret_cast<HotPatchData*>(function.byte_ptr - 5);

		VirtualProtect(hotpatch, 7, PAGE_EXECUTE_READWRITE, &protection);

		original_function = function.byte_ptr + 2;
		hotpatch->JMP = 0xE9;
		hotpatch->function = reinterpret_cast<void*>(new_function.byte_ptr - function.byte_ptr);
		hotpatch->JMP_back = 0xF9EB;

		patched = true;

		VirtualProtect(hotpatch, 7, protection, &protection);

		return original_function;
	}

	void UnPatch()
	{
		DWORD protection{ 0 };

		VirtualProtect(hotpatch, 7, PAGE_EXECUTE_READWRITE, &protection);

		hotpatch->JMP_back = 0xFF8B;
		hotpatch->JMP = 0x90;
		hotpatch->function = reinterpret_cast<void*>(0x90909090);

		patched = false;

		VirtualProtect(hotpatch, 7, protection, &protection);
	}

	bool IsPatched() const
	{
		return patched;
	}

private:
	Ptr  function;
	Ptr  new_function;
	bool unpatch_in_dtor;
	bool patched;
#pragma pack(push, 1)
	struct HotPatchData
	{
		BYTE  JMP;
		void* function;
		WORD  JMP_back;
	} *hotpatch;
#pragma pack(pop)

	HotPatch() = delete;
	HotPatch(const HotPatch& other) = delete;
	HotPatch(HotPatch&& other) = delete;

	HotPatch& operator=(const HotPatch& other) = delete;
	HotPatch& operator=(HotPatch&& other) = delete;
};

//=====================================================================================