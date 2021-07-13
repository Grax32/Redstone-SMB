using System;

namespace RedstoneSmb.Services.ServerService.Enums
{
    [Flags]
    public enum Permissions : uint
    {
        PermFileRead = 0x00000001,
        PermFileWrite = 0x00000002,
        PermFileCreate = 0x00000004,
        AccessExec = 0x00000008,
        AccessDelete = 0x00000010,
        AccessAtrib = 0x00000020,
        AccessPerm = 0x00000040
    }
}