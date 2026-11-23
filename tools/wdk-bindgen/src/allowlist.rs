pub const FUNCTIONS: &[&str] = &[
    "Fwps(Callout(Register[0-3]|UnregisterBy(Id|Key)[0-3])|Flow(AssociateContext|RemoveContext)[0-3]|InjectionHandle(Create|Destroy)[0-3]|QueryPacketInjectionState[0-3]|InjectTransportReceiveAsync[0-3]|(Allocate|Free)CloneNetBufferList[0-3]|AllocateNetBufferAndNetBufferList[0-3]|FreeNetBufferList[0-3]|ConstructIpHeaderForTransportPacket[0-3]|GetPacketListSecurityInformation[0-3])",
    "Fwpm(BfeState(Get|SubscribeChanges|UnsubscribeChanges)[0-3]|Engine(Open|Close)[0-3]|Transaction(Begin|Commit|Abort)[0-3]|(Provider|SubLayer|Callout)(Add|DeleteByKey|GetByKey)[0-3]|Filter(Add|DeleteById|DeleteByKey|GetByKey)[0-3]|FreeMemory[0-3])",
    "Ndis(GetDataBuffer|AllocateNetBufferAndNetBufferList|FreeNetBufferList|AllocateNetBufferListPool|FreeNetBufferListPool|AllocateMdl|FreeMdl|AllocateGenericObject|FreeGenericObject)",
    "Io(CreateDevice|DeleteDevice|CreateSymbolicLink|DeleteSymbolicLink|AllocateMdl|FreeMdl|CsqInitialize(Ex)?|CsqInsertIrp(Ex)?|CsqRemoveIrp|CsqRemoveNextIrp|AcquireRemoveLockEx|ReleaseRemoveLockEx|ReleaseRemoveLockAndWaitEx)",
    "WdmlibIoCreateDeviceSecure",
    "Ex(AllocatePool2|FreePool(WithTag)?|InitializeRundownProtection|AcquireRundownProtection|ReleaseRundownProtection|WaitForRundownProtectionRelease|RundownCompleted)",
    "Ke(QueryInterruptTimePrecise|InitializeEvent|SetEvent|ClearEvent|WaitForSingleObject|BugCheckEx|AreAllApcsDisabled)",
    "ZwCreateFile",
    "ObCloseHandle",
    "MmBuildMdlForNonPagedPool",
    "gnunet_wfp_.*",
];
pub const TYPES: &[&str] = &[
    "_?FWP[SM]?_.*",
    "_?(NET_BUFFER(_LIST)?|NET_BUFFER_LIST_POOL_PARAMETERS|NDIS_GENERIC_OBJECT|NDIS_OBJECT_HEADER|MDL|GUID)",
    "_?(DRIVER_OBJECT|DEVICE_OBJECT|FILE_OBJECT|IRP|IO_STACK_LOCATION|IO_STATUS_BLOCK|UNICODE_STRING|LIST_ENTRY|KSPIN_LOCK|KIRQL|EX_RUNDOWN_REF|IO_REMOVE_LOCK|IO_CSQ|KEVENT|LARGE_INTEGER)",
    "P?(DRIVER_INITIALIZE|DRIVER_UNLOAD|DRIVER_DISPATCH|IO_CANCEL_ROUTINE)",
];
pub const VARIABLES: &[&str] = &[
    "FWP[SM]?_.*",
    "NDIS_(OBJECT_TYPE_.*|SIZEOF_.*|PROTOCOL_ID_.*)",
    "GNUNET_WFP_.*",
    "(FILE_DEVICE_.*|FILE_(READ|WRITE|ANY)_ACCESS|METHOD_.*|DO_.*|IRP_MJ_.*|SL_.*|PASSIVE_LEVEL|DISPATCH_LEVEL|APC_LEVEL|POOL_FLAG_.*|NonPagedPool.*)",
];
