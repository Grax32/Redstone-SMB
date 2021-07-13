using System;

namespace RedstoneSmb.NTFileStore.Enums.FileInformation
{
    [Flags]
    public enum ExtendedAttributeFlags : byte
    {
        FileNeedEa = 0x80
    }
}