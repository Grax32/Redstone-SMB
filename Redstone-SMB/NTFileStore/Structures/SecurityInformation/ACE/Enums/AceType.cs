namespace RedstoneSmb.NTFileStore.Structures.SecurityInformation.ACE.Enums
{
    public enum AceType : byte
    {
        AccessAllowedAceType = 0x00,
        AccessDeniedAceType = 0x01,
        SystemAuditAceType = 0x02,
        SystemAlarmAceType = 0x03,
        AccessAllowedCompoundAceType = 0x04,
        AccessAllowedObjectAceType = 0x05,
        AccessDeniedObjectAceType = 0x06,
        SystemAuditObjectAceType = 0x07,
        SystemAlarmObjectAceType = 0x08,
        AccessAllowedCallbackAceType = 0x09,
        AccessDeniedCallbackAceType = 0x0A,
        AccessAllowedCallbackObjectAceType = 0x0B,
        AccessDeniedCallbackObjectAceType = 0x0C,
        SystemAuditCallbackAceType = 0x0D,
        SystemAlarmCallbackAceType = 0x0E,
        SystemAuditCallbackObjectAceType = 0x0F,
        SystemAlarmCallbackObjectAceType = 0x10,
        SystemMandatoryLabelAceType = 0x11,
        SystemResourceAttributeAceType = 0x12,
        SystemScopedPolicyIdAceType = 0x13
    }
}