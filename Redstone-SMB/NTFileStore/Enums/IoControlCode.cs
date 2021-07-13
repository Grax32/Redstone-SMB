namespace RedstoneSmb.NTFileStore.Enums
{
    public enum IoControlCode : uint
    {
        FsctlDfsGetReferrals = 0x00060194, // SMB2-specific processing
        FsctlDfsGetReferralsEx = 0x000601B0, // SMB2-specific processing
        FsctlIsPathnameValid = 0x0009002C,
        FsctlGetCompression = 0x0009003C,
        FsctlFilesystemGetStatistics = 0x00090060,
        FsctlQueryFatBpb = 0x00090058,
        FsctlGetNtfsVolumeData = 0x00090064,
        FsctlGetRetrievalPointers = 0x00090073,
        FsctlFindFilesBySid = 0x0009008F,
        FsctlSetObjectId = 0x00090098,
        FsctlGetObjectId = 0x0009009C,
        FsctlDeleteObjectId = 0x000900A0,
        FsctlSetReparsePoint = 0x000900A4, // SMB2-specific processing
        FsctlGetReparsePoint = 0x000900A8,
        FsctlDeleteReparsePoint = 0x000900AC,
        FsctlSetObjectIdExtended = 0x000900BC,
        FsctlCreateOrGetObjectId = 0x000900C0,
        FsctlSetSparse = 0x000900C4,
        FsctlReadFileUsnData = 0x000900EB,
        FsctlWriteUsnCloseRecord = 0x000900EF,
        FsctlQuerySparingInfo = 0x00090138,
        FsctlQueryOnDiskVolumeInfo = 0x0009013C,
        FsctlSetZeroOnDeallocation = 0x00090194,
        FsctlQueryFileRegions = 0x00090284,
        FsctlQuerySharedVirtualDiskSupport = 0x00090300,
        FsctlSvhdxSyncTunnelRequest = 0x00090304,
        FsctlStorageQosControl = 0x00090350,
        FsctlSvhdxAsyncTunnelRequest = 0x00090364,
        FsctlQueryAllocatedRanges = 0x000940CF,
        FsctlOffloadRead = 0x00094264,
        FsctlSetZeroData = 0x000980C8,
        FsctlSetDefectManagement = 0x00098134,
        FsctlFileLevelTrim = 0x00098208, // SMB2-specific processing
        FsctlOffloadWrite = 0x00098268,
        FsctlDuplicateExtentsToFile = 0x00098344,
        FsctlSetCompression = 0x0009C040,
        FsctlPipeWait = 0x00110018, // SMB2-specific processing
        FsctlPipePeek = 0x0011400C, // SMB2-specific processing
        FsctlPipeTransceive = 0x0011C017, // SMB2-specific processing
        FsctlSrvRequestResumeKey = 0x00140078, // SMB2-specific processing
        FsctlLmrSetLinkTrackingInformation = 0x001400EC,
        FsctlValidateNegotiateInfo = 0x00140204, // SMB2-specific processing
        FsctlLmrRequestResiliency = 0x001401D4, // SMB2-specific processing
        FsctlQueryNetworkInterfaceInfo = 0x001401FC, // SMB2-specific processing
        FsctlSrvEnumerateSnapshots = 0x00144064, // SMB2-specific processing
        FsctlSrvCopychunk = 0x001440F2, // SMB2-specific processing
        FsctlSrvReadHash = 0x001441BB, // SMB2-specific processing
        FsctlSrvCopychunkWrite = 0x001480F2 // SMB2-specific processing
    }
}