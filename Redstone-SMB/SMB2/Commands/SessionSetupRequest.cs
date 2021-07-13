/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using RedstoneSmb.SMB2.Enums;
using RedstoneSmb.SMB2.Enums.Negotiate;
using RedstoneSmb.SMB2.Enums.SessionSetup;
using ByteReader = RedstoneSmb.Utilities.ByteUtils.ByteReader;
using ByteWriter = RedstoneSmb.Utilities.ByteUtils.ByteWriter;
using LittleEndianConverter = RedstoneSmb.Utilities.Conversion.LittleEndianConverter;
using LittleEndianWriter = RedstoneSmb.Utilities.ByteUtils.LittleEndianWriter;

namespace RedstoneSmb.SMB2.Commands
{
    /// <summary>
    ///     SMB2 SESSION_SETUP Request
    /// </summary>
    public class SessionSetupRequest : Smb2Command
    {
        public const int FixedSize = 24;
        public const int DeclaredSize = 25;
        public Capabilities Capabilities; // Values other than SMB2_GLOBAL_CAP_DFS should be treated as reserved.
        public uint Channel;
        public SessionSetupFlags Flags;
        public ulong PreviousSessionId;
        public byte[] SecurityBuffer = new byte[0];
        private ushort _securityBufferLength;
        private ushort _securityBufferOffset;
        public SecurityMode SecurityMode;

        private readonly ushort _structureSize;

        public SessionSetupRequest() : base(Smb2CommandName.SessionSetup)
        {
            _structureSize = DeclaredSize;
        }

        public SessionSetupRequest(byte[] buffer, int offset) : base(buffer, offset)
        {
            _structureSize = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 0);
            Flags = (SessionSetupFlags) ByteReader.ReadByte(buffer, offset + Smb2Header.Length + 2);
            SecurityMode = (SecurityMode) ByteReader.ReadByte(buffer, offset + Smb2Header.Length + 3);
            Capabilities = (Capabilities) LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 4);
            Channel = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 8);
            _securityBufferOffset = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 12);
            _securityBufferLength = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 14);
            PreviousSessionId = LittleEndianConverter.ToUInt64(buffer, offset + Smb2Header.Length + 16);
            if (_securityBufferLength > 0)
                SecurityBuffer = ByteReader.ReadBytes(buffer, offset + _securityBufferOffset, _securityBufferLength);
        }

        public override int CommandLength => FixedSize + SecurityBuffer.Length;

        public override void WriteCommandBytes(byte[] buffer, int offset)
        {
            _securityBufferOffset = 0;
            _securityBufferLength = (ushort) SecurityBuffer.Length;
            if (SecurityBuffer.Length > 0) _securityBufferOffset = Smb2Header.Length + FixedSize;
            LittleEndianWriter.WriteUInt16(buffer, offset + 0, _structureSize);
            ByteWriter.WriteByte(buffer, offset + 2, (byte) Flags);
            ByteWriter.WriteByte(buffer, offset + 3, (byte) SecurityMode);
            LittleEndianWriter.WriteUInt32(buffer, offset + 4, (uint) Capabilities);
            LittleEndianWriter.WriteUInt32(buffer, offset + 8, Channel);
            LittleEndianWriter.WriteUInt16(buffer, offset + 12, _securityBufferOffset);
            LittleEndianWriter.WriteUInt16(buffer, offset + 14, _securityBufferLength);
            LittleEndianWriter.WriteUInt64(buffer, offset + 16, PreviousSessionId);
            ByteWriter.WriteBytes(buffer, offset + FixedSize, SecurityBuffer);
        }
    }
}