namespace RedstoneSmb.Enums
{
    // All Win32 error codes MUST be in the range 0x0000 to 0xFFFF
    public enum Win32Error : ushort
    {
        ErrorSuccess = 0x0000,
        ErrorAccessDenied = 0x0005,
        ErrorSharingViolation = 0x0020,
        ErrorNotSupported = 0x0032,
        ErrorInvalidParameter = 0x0057,
        ErrorDiskFull = 0x0070,
        ErrorInvalidName = 0x007B,
        ErrorInvalidLevel = 0x007C,
        ErrorDirNotEmpty = 0x0091,
        ErrorBadPathname = 0x00A1,
        ErrorAlreadyExists = 0x00B7,
        ErrorNoToken = 0x03F0,
        ErrorLogonFailure = 0x052E,
        ErrorAccountRestriction = 0x052F,
        ErrorInvalidLogonHours = 0x0530,
        ErrorInvalidWorkstation = 0x0531,
        ErrorPasswordExpired = 0x0532,
        ErrorAccountDisabled = 0x0533,
        ErrorLogonTypeNotGranted = 0x0569,
        ErrorAccountExpired = 0x0701,
        ErrorPasswordMustChange = 0x0773,
        ErrorAccountLockedOut = 0x0775,
        NerrNetNameNotFound = 0x0906
    }
}