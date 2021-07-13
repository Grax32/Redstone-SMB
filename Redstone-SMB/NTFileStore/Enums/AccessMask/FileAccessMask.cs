using System;

namespace RedstoneSmb.NTFileStore.Enums.AccessMask
{
    /// <summary>
    ///     [MS-SMB] 2.2.1.4.1 - File_Pipe_Printer_Access_Mask
    ///     [MS-SMB2] 2.2.13.1.1 - File_Pipe_Printer_Access_Mask
    /// </summary>
    [Flags]
    public enum FileAccessMask : uint
    {
        FileReadData = 0x00000001,
        FileWriteData = 0x00000002,
        FileAppendData = 0x00000004,
        FileReadEa = 0x00000008,
        FileWriteEa = 0x00000010,
        FileExecute = 0x00000020,
        FileReadAttributes = 0x00000080,
        FileWriteAttributes = 0x00000100,
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