using System;

namespace RedstoneSmb.NTFileStore.Enums.SecurityInformation
{
    /// <summary>
    ///     [MS-DTYP] 2.4.7 - SECURITY_INFORMATION
    /// </summary>
    [Flags]
    public enum SecurityInformation : uint
    {
        OwnerSecurityInformation = 0x00000001,
        GroupSecurityInformation = 0x00000002,
        DaclSecurityInformation = 0x00000004,
        SaclSecurityInformation = 0x00000008,
        LabelSecurityInformation = 0x00000010,
        AttributeSecurityInformation = 0x00000020,
        ScopeSecurityInformation = 0x00000040,
        BackupSecurityInformation = 0x00010000
    }
}