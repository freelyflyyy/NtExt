#pragma once
#include <iostream>
#include <NtCallExt.h>
#include <NtExt/invoker/NtExtInvokers.hpp>

using namespace NtExt;

int main() {
    X64NtCallExt ext;
    DWORD64 nt64 = ext.GetNtdll64();
    std::cout << "0x" << std::hex << nt64 << std::endl;
    DWORD64 func = ext.GetFunc64("NtClose");
    Call(func) ( (DWORD64) -1 );
    system("pause");
    return 0;
}