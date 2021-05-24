//=====================================================================================

#include "Hook.hpp"

#include <Psapi.h>
#include <fstream>

//=====================================================================================

MODULEINFO get_module_info(const char* name)
{
	MODULEINFO module_info = { nullptr };
	auto module_handle = GetModuleHandle(name);

	if (!module_handle)
		return module_info;

	GetModuleInformation(GetCurrentProcess(), module_handle, &module_info, sizeof(MODULEINFO));
	return module_info;
}

//=====================================================================================

static auto _module_info = get_module_info(nullptr);
const static auto _module_base = reinterpret_cast<std::uintptr_t>(_module_info.lpBaseOfDll);
const static auto _decryption = _module_base + 0x3300;
const static auto _decryption_call = _module_base + 0x3890;

//=====================================================================================

char* decryption_h(char* _this);
typedef decltype(decryption_h)* decryption_t;
decryption_t decryption_o = reinterpret_cast<decryption_t>(_decryption);
Hook decryption_hook{ x86Instruction::CALL, reinterpret_cast<void*>(_decryption_call), &decryption_h };

//=====================================================================================

char* decryption_h(char* _this)
{
	std::ofstream file;

	file.open("bo2.dll", std::ios::out | std::ios::binary);
	file.write(_this, 552960);
	file.close();

	return decryption_o(_this);
}

//=====================================================================================

void init() 
{
	decryption_hook.SetHook();
}

//=====================================================================================

void free() 
{
	decryption_hook.UnHook();
}

//=====================================================================================

BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) 
{
	DisableThreadLibraryCalls(hinstDLL);

	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		init();
		return TRUE;

	case DLL_PROCESS_DETACH:
		free();
		return TRUE;

	default:
		return FALSE;
	}
}

//=====================================================================================