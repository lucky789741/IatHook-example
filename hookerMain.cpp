#include "logger.hpp"
#include "hook.hpp"

int main()
{
	Logger::getInstance().print("紀錄開始");
	HANDLE hProc = GetCurrentProcess();
	int pid = GetProcessId(hProc);
	Logger::getInstance().print("Hook前PID:"+std::to_string(pid));
	HOOK::IatHookGetCurrentProcess();
	hProc = GetCurrentProcess();
	pid = GetProcessId(hProc);
	Logger::getInstance().print("Hook後PID:" + std::to_string(pid));
	HOOK::IatUnHookGetCurrentProcess();
	hProc = GetCurrentProcess();
	pid = GetProcessId(hProc);
	Logger::getInstance().print("UnHook後PID:" + std::to_string(pid));
}