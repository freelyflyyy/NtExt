#include <iostream>
#include <NtCallExt.h>

using namespace MemX;

int main() {
	DWORD64 ntdllBase = GET_FUNC(L"ntdll.dll", "NtClose") - 0x1000; //get ntdll base by a known function
	std::cout << "ntdll.dll base: 0x" << std::hex << ntdllBase << std::endl;
	system("pause");
    return 0;
}