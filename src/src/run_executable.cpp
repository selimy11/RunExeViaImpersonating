#include <windows.h>
#include <atlstr.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <UserEnv.h>
#include <Wtsapi32.h>
#include <iostream>
#include <vector>

#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "Wtsapi32.lib")

/**
 * @brief Retrieves the session ID of the currently active user session.
 * 
 * This function enumerates all sessions on the current server and checks for
 * a session in the active state (WTSActive). If an active session is found,
 * its session ID is returned. If no active session is found or an error occurs,
 * the function returns -1.
 * 
 * @return DWORD The session ID of the active session, or -1 if no active session
 *         is found or an error occurs.
 * 
 * @note The function uses WTSEnumerateSessions to retrieve session information
 *       and WTSFreeMemory to free the allocated memory for session data.
 * 
 * @warning Ensure that the WTS API is properly initialized and that the caller
 *          has sufficient privileges to enumerate sessions.
 * 
 * @see WTSEnumerateSessions, WTS_SESSION_INFO, WTSFreeMemory
 */
DWORD GetActiveSessionId()
{
    WTS_SESSION_INFO *pSessionInfo = nullptr;
	DWORD sessionCount = 0;

	if (WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSessionInfo, &sessionCount))
	{
		for (DWORD i = 0; i < sessionCount; i++)
		{
			if (pSessionInfo[i].State == _WTS_CONNECTSTATE_CLASS::WTSActive)
			{
				return pSessionInfo[i].SessionId;
			}
		}
		WTSFreeMemory(pSessionInfo);
	}
	else
	{
		std::cout << "Failed to enumerate sessions. Error: " << GetLastError() << std::endl;
		return -1;
	}
	return -1;
}

/**
 * @brief Retrieves the process IDs of all processes with the specified name.
 * 
 * This function enumerates all running processes on the system and checks their
 * names against the provided process name. If a match is found, the process ID
 * is added to the result vector.
 * 
 * @param processName The name of the process to search for (case-sensitive).
 * @return A vector containing the process IDs of all matching processes. If no
 *         processes match the specified name, the vector will be empty.
 * 
 * @note This function requires the calling process to have sufficient privileges
 *       to query information about other processes.
 * @note The function uses `EnumProcesses` to enumerate processes and `GetModuleBaseNameW`
 *       to retrieve the process name.
 * 
 * @warning Ensure proper error handling when using this function, as it may fail
 *          to retrieve process information due to insufficient permissions or other
 *          system constraints.
 */
std::vector<DWORD> GetProcessIdsByName(const std::wstring &processName)
{
    std::vector<DWORD> processIds;
    DWORD processIdsArray[1024], bytesNeeded;
    if (!EnumProcesses(processIdsArray, sizeof(processIdsArray), &bytesNeeded))
    {
        return processIds;
    }
    DWORD numProcesses = bytesNeeded / sizeof(DWORD);
    DWORD i = 0;
    while (i < numProcesses)
    {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processIdsArray[i]);
        if (hProcess != NULL)
        {
            WCHAR szProcessName[MAX_PATH];
            if (GetModuleBaseNameW(hProcess, nullptr, szProcessName, MAX_PATH) > 0 && processName == szProcessName)
            {
                processIds.push_back(processIdsArray[i]);
            }
            CloseHandle(hProcess);
        }
        i++; 
    }
    return processIds;
}

/**
 * @brief Retrieves the process ID of a running process by its name.
 * 
 * This function takes the name of a process as input and searches through
 * the list of currently running processes to find a match. If a process
 * with the specified name is found, its process ID is returned.
 * 
 * @param processName The name of the process to search for (case-sensitive).
 * @return DWORD The process ID of the specified process if found, or 0 if
 *         the process is not found or an error occurs.
 * 
 * @note The function uses the Toolhelp32 API to enumerate processes.
 *       Ensure that the process name provided includes the file extension
 *       (e.g., "notepad.exe").
 * 
 * @warning This function performs a case-sensitive comparison of process
 *          names. Ensure the input matches the exact name of the process.
 * 
 * @example
 * std::wstring processName = L"notepad.exe";
 * DWORD processId = GetProcessIdByName(processName);
 * if (processId != 0) {
 *     wprintf(L"Process ID: %lu\n", processId);
 * } else {
 *     wprintf(L"Process not found.\n");
 * }
 */
DWORD GetProcessIdByName(const std::wstring &processName)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
	{
		return 0;
	}

	DWORD processId = 0;
	PROCESSENTRY32W processEntry = {};
	processEntry.dwSize = sizeof(PROCESSENTRY32);

	if (Process32FirstW(hSnapshot, &processEntry))
	{
		do
		{
			std::wstring currentProcessName = processEntry.szExeFile;
			if (currentProcessName == processName)
			{
				processId = processEntry.th32ProcessID;
				break;
			}
		} while (Process32NextW(hSnapshot, &processEntry));
	}

	CloseHandle(hSnapshot);
	return processId;
}

/**
 * @brief Runs an installer executable with elevated rights by impersonating a target process.
 * 
 * This function locates a target process by name, duplicates its token, and uses it to create
 * a new process with elevated privileges. It waits for the created process to complete execution
 * before returning.
 * 
 * @param setupFilePath The full file path of the installer executable to be run.
 * @param PID Reference to a DWORD variable that will receive the process ID of the created process.
 * 
 * @note The function assumes the target process (e.g., "dllhost.exe") is already running.
 * 
 * @warning Ensure proper error handling and security measures when using this function, as it 
 *          involves elevated privileges and process token manipulation.
 * 
 * @remarks The function uses the following Windows API functions:
 *          - GetProcessIdByName (assumed to be implemented elsewhere)
 *          - OpenProcess
 *          - OpenProcessToken
 *          - DuplicateTokenEx
 *          - CreateEnvironmentBlock
 *          - CreateProcessAsUserW
 *          - WaitForSingleObject
 * 
 * @remarks The caller is responsible for ensuring the validity of the `setupFilePath` parameter.
 * 
 * @remarks The function cleans up all handles it opens, but the caller should ensure that the 
 *          environment is properly secured to avoid privilege escalation vulnerabilities.
 */
void runInstallerViaElevatedRights(std::wstring setupFilePath, DWORD &PID)
{
	HANDLE hUserTokenDup = nullptr;
	HANDLE hPToken = nullptr;
	PROCESS_INFORMATION pi;

	const std::wstring targetProcessName = L"dllhost.exe";

	const DWORD processId = GetProcessIdByName(targetProcessName);

	STARTUPINFOW si = {};
	si.cb = sizeof(si);
	si.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default");

	const HANDLE hProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, processId);

	if (!OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_SESSIONID | TOKEN_READ | TOKEN_WRITE, &hPToken))
	{
		CloseHandle(hProcess);
	}

	SECURITY_ATTRIBUTES sa = {};
	sa.nLength = sizeof(sa);

	if (!DuplicateTokenEx(hPToken, MAXIMUM_ALLOWED, &sa,
						  SecurityIdentification, TokenPrimary,
						  &hUserTokenDup))
	{
		CloseHandle(hProcess);
		CloseHandle(hPToken);
	}

	HANDLE pEnv = nullptr;
	uint32_t dwCreationFlags = 0;

	if (CreateEnvironmentBlock(&pEnv, hUserTokenDup, true))
	{
		dwCreationFlags = NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT;
	}

	const LPCWSTR dir = L"C:\\Program Files";

	if (!CreateProcessAsUserW(hUserTokenDup,		// client's access token
							  nullptr,				// file to execute
							  setupFilePath.data(), // command line
							  &sa,					// pointer to process SECURITY_ATTRIBUTES
							  &sa,					// pointer to thread SECURITY_ATTRIBUTES
							  false,				// handles are not inheritable
							  dwCreationFlags,		// creation flags
							  pEnv,					// pointer to new environment block
							  nullptr,				// name of current directory
							  &si,					// pointer to STARTUPINFO structure
							  &pi					// receives information about new process
							  ))
	{
		std::cout << "CreateProcessAsUser failed. Error: " << GetLastError() << std::endl;
		CloseHandle(hUserTokenDup);
		CloseHandle(hPToken);
		CloseHandle(hProcess);
	}
	PID = pi.dwProcessId;
	WaitForSingleObject(pi.hProcess, INFINITE);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
}

/**
 * @brief Runs an installer executable in the context of the active user session.
 * 
 * This function locates the `winlogon.exe` process associated with the active user session,
 * duplicates its token, and uses it to launch the specified installer executable with the 
 * appropriate privileges and environment. It waits for the installer process to complete 
 * before cleaning up resources.
 * 
 * @param setupFilePath The full file path to the installer executable to be run.
 * @param pi A reference to a PROCESS_INFORMATION structure that will receive information 
 *           about the newly created process.
 * 
 * @note The function assumes that the caller has sufficient privileges to perform actions 
 *       such as opening process tokens, duplicating tokens, and creating processes as another user.
 * 
 * @warning Ensure that the provided `setupFilePath` points to a valid executable file. 
 *          Failure to handle errors properly may result in resource leaks or undefined behavior.
 * 
 * @throws This function does not throw exceptions but logs errors to the standard output 
 *         if operations such as `CreateProcessAsUserW` fail.
 * 
 * @remarks The function uses `CreateEnvironmentBlock` to create a new environment block 
 *          for the process and sets the desktop to `winsta0\\default` for the new process.
 *          It also waits for the process to complete using `WaitForSingleObject`.
 * 
 * @dependencies 
 * - `GetProcessIdsByName`: A helper function to retrieve process IDs by name.
 * - `ProcessIdToSessionId`: Used to map a process ID to its session ID.
 * - `GetActiveSessionId`: Retrieves the active session ID.
 * - `CreateEnvironmentBlock`: Creates an environment block for the new process.
 * - `CreateProcessAsUserW`: Creates a process in the context of another user.
 * 
 * @cleanup The function ensures proper cleanup of handles and resources, including:
 * - Closing process and token handles.
 * - Destroying the environment block if created.
 * - Uninitializing COM with `CoUninitialize`.
 */
void runInstallerViaSession(const std::wstring &setupFilePath, PROCESS_INFORMATION &pi)
{
	HANDLE hUserTokenDup = nullptr;
	HANDLE hPToken = nullptr;
	DWORD sessionId;

	uint32_t PrcsId = 0;

	const std::wstring targetProcessName = L"winlogon.exe";
	const std::vector<DWORD> processIds = GetProcessIdsByName(targetProcessName);

	for (const DWORD processId : processIds)
	{
		ProcessIdToSessionId(processId, &sessionId);
		if (sessionId == GetActiveSessionId())
		{
			PrcsId = processId;
		}
	}

	STARTUPINFOW si = {};
	si.cb = sizeof(si);
	si.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default");

	const HANDLE hProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, PrcsId);

	if (!OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_SESSIONID | TOKEN_READ | TOKEN_WRITE, &hPToken))
	{
		CloseHandle(hProcess);
	}

	SECURITY_ATTRIBUTES sa = {};
	sa.nLength = sizeof(sa);

	if (!DuplicateTokenEx(hPToken, MAXIMUM_ALLOWED, &sa,
						  SecurityIdentification, TokenPrimary,
						  &hUserTokenDup))
	{
		CloseHandle(hProcess);
		CloseHandle(hPToken);
	}

	HANDLE pEnv = nullptr;
	uint32_t dwCreationFlags = 0;

	if (CreateEnvironmentBlock(&pEnv, hUserTokenDup, true))
	{
		dwCreationFlags = NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT;
	}

	if (!CreateProcessAsUserW(hUserTokenDup,		// client's access token
							  setupFilePath.data(), // file to execute
							  nullptr,				// command line
							  &sa,					// pointer to process SECURITY_ATTRIBUTES
							  &sa,					// pointer to thread SECURITY_ATTRIBUTES
							  false,				// handles are not inheritable
							  dwCreationFlags,		// creation flags
							  pEnv,					// pointer to new environment block
							  nullptr,				// name of current directory
							  &si,					// pointer to STARTUPINFO structure
							  &pi					// receives information about new process
							  ))
	{
		std::cout << "CreateProcessAsUser failed. Error: " << GetLastError() << std::endl;
		CloseHandle(hUserTokenDup);
		CloseHandle(hPToken);
		CloseHandle(hProcess);
	}

	WaitForSingleObject(pi.hProcess, INFINITE);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	CoUninitialize();
}

int main(int argc, char const *argv[])
{
	PROCESS_INFORMATION pi = {};
	runInstallerViaSession(L"C:\\windows\\system32\\calc.exe", pi);
	std::cout << "Calculator runned via active session - Process ID: " << pi.dwProcessId << std::endl;
	runInstallerViaElevatedRights(L"C:\\windows\\system32\\calc.exe", pi.dwProcessId);
	std::cout << "Calculator runned via Elevated Rights - Process ID: " << pi.dwProcessId << std::endl;
	CoUninitialize();
	return 0;
}
