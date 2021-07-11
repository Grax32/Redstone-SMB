namespace SMBLibrary.RPC.Enums
{
    public enum RejectionReason : ushort
    {
        NotSpecified,
        AbstractSyntaxNotSupported,
        ProposedTransferSyntaxesNotSupported,
        LocalLimitExceeded
    }
}