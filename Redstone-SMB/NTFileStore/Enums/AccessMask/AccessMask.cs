using System;

namespace RedstoneSmb.NTFileStore.Enums.AccessMask
{
    /// <summary>
    ///     [MS-DTYP] 2.4.3 - ACCESS_MASK
    /// </summary>
    [Flags]
    public enum AccessMask : uint
    {
        // The bits in positions 16 through 31 are object specific.
        Delete = 0x00010000,
        ReadControl = 0x00020000,
        WriteDac = 0x00040000,
        WriteOwner = 0x00080000,
        Synchronize = 0x00100000,
        AccessSystemSecurity = 0x01000000,
        MaximumAllowed = 0x02000000,
        GenericAll = 0x10000000,
        GenericExecute = 0x20000000,
        GenericWrite = 0x40000000,
        GenericRead = 0x80000000
    }
}