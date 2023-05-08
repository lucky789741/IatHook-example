#include "logger.hpp"
#include "hook.hpp"

int main()
{
	Logger::getInstance().print("�����}�l");
	HANDLE hProc = GetCurrentProcess();
	int pid = GetProcessId(hProc);
	Logger::getInstance().print("Hook�ePID:"+std::to_string(pid));
	HOOK::IatHookGetCurrentProcess();
	hProc = GetCurrentProcess();
	pid = GetProcessId(hProc);
	Logger::getInstance().print("Hook��PID:" + std::to_string(pid));
	HOOK::IatUnHookGetCurrentProcess();
	hProc = GetCurrentProcess();
	pid = GetProcessId(hProc);
	Logger::getInstance().print("UnHook��PID:" + std::to_string(pid));
}