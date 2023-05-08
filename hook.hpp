#pragma once
#include "logger.hpp"
#include "includes.hpp"

typedef DWORD_PTR(WINAPI* pFnGetCurrentProcess)();
namespace HOOK
{

	HANDLE WINAPI MyGetCurrentProcess();

	void IatHookGetCurrentProcess();

	void IatUnHookGetCurrentProcess();
}