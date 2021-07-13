/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using RedstoneSmb.SMB2.Enums;
using RedstoneSmb.SMB2.Enums.SessionSetup;
using ByteReader = RedstoneSmb.Utilities.ByteUtils.ByteReader;
using ByteWriter = RedstoneSmb.Utilities.ByteUtils.ByteWriter;
using LittleEndianConverter = RedstoneSmb.Utilities.Conversion.LittleEndianConverter;
using LittleEndianWriter = RedstoneSmb.Utilities.ByteUtils.LittleEndianWriter;

namespace RedstoneSmb.SMB2.Commands
{
    /// <summary>
    ///     SMB2 SESSION_SETUP Response
    /// </summary>
    public class SessionSetupResponse : Smb2Command
    {
        public const int FixedSize = 8;
        public const int DeclaredSize = 9;
        public byte[] SecurityBuffer = new byte[0];
        private ushort _securityBufferLength;
        private ushort _securityBufferOffset;
        public SessionFlags SessionFlags;

        private readonly ushort _structureSize;

        public SessionSetupResponse() : base(Smb2CommandName.SessionSetup)
        {
            Header.IsResponse = true;
            _structureSize = DeclaredSize;
        }

        public SessionSetupResponse(byte[] buffer, int offset) : base(buffer, offset)
        {
            _structureSize = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 0);
            SessionFlags = (SessionFlags) LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 2);
            _securityBufferOffset = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 4);
            _securityBufferLength = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 6);
            SecurityBuffer = ByteReader.ReadBytes(buffer, offset + _securityBufferOffset, _securityBufferLength);
        }

        public override int CommandLength => FixedSize + SecurityBuffer.Length;

        public override void WriteCommandBytes(byte[] buffer, int offset)
        {
            _securityBufferOffset = 0;
            _securityBufferLength = (ushort) SecurityBuffer.Length;
            if (SecurityBuffer.Length > 0) _securityBufferOffset = Smb2Header.Length + FixedSize;
            LittleEndianWriter.WriteUInt16(buffer, offset + 0, _structureSize);
            LittleEndianWriter.WriteUInt16(buffer, offset + 2, (ushort) SessionFlags);
            LittleEndianWriter.WriteUInt16(buffer, offset + 4, _securityBufferOffset);
            LittleEndianWriter.WriteUInt16(buffer, offset + 6, _securityBufferLength);
            ByteWriter.WriteBytes(buffer, offset + 8, SecurityBuffer);
        }
    }
}