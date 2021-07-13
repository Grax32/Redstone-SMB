using System;

namespace SMBLibrary.NTFileStore.Enums.FileInformation
{
    [Flags]
    public enum ExtendedAttributeFlags : byte
    {
        FILE_NEED_EA = 0x80
    }
}