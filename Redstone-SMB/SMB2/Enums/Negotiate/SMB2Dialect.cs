namespace RedstoneSmb.SMB2.Enums.Negotiate
{
    public enum Smb2Dialect : ushort
    {
        Smb202 = 0x0202, // SMB 2.0.2
        Smb210 = 0x0210, // SMB 2.1
        Smb300 = 0x0300, // SMB 3.0
        Smb302 = 0x0302, // SMB 3.0.2
        Smb311 = 0x0311, // SMB 3.1.1

        /// <summary>
        ///     indicates that the server implements SMB 2.1 or future dialect revisions and expects
        ///     the client to send a subsequent SMB2 Negotiate request to negotiate the actual SMB 2
        ///     Protocol revision to be used.
        ///     The wildcard revision number is sent only in response to a multi-protocol negotiate
        ///     request with the "SMB 2.???" dialect string.
        /// </summary>
        Smb2Xx = 0x02FF // SMB 2.xx
    }
}