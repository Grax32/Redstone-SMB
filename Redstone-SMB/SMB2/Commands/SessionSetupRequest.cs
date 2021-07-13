/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.SMB2.Enums;
using SMBLibrary.SMB2.Enums.Negotiate;
using SMBLibrary.SMB2.Enums.SessionSetup;
using SMBLibrary.Utilities.ByteUtils;
using SMBLibrary.Utilities.Conversion;
using ByteReader = SMBLibrary.Utilities.ByteUtils.ByteReader;
using ByteWriter = SMBLibrary.Utilities.ByteUtils.ByteWriter;
using LittleEndianConverter = SMBLibrary.Utilities.Conversion.LittleEndianConverter;
using LittleEndianWriter = SMBLibrary.Utilities.ByteUtils.LittleEndianWriter;

namespace SMBLibrary.SMB2.Commands
{
    /// <summary>
    ///     SMB2 SESSION_SETUP Request
    /// </summary>
    public class SessionSetupRequest : SMB2Command
    {
        public const int FixedSize = 24;
        public const int DeclaredSize = 25;
        public Capabilities Capabilities; // Values other than SMB2_GLOBAL_CAP_DFS should be treated as reserved.
        public uint Channel;
        public SessionSetupFlags Flags;
        public ulong PreviousSessionId;
        public byte[] SecurityBuffer = new byte[0];
        private ushort SecurityBufferLength;
        private ushort SecurityBufferOffset;
        public SecurityMode SecurityMode;

        private readonly ushort StructureSize;

        public SessionSetupRequest() : base(SMB2CommandName.SessionSetup)
        {
            StructureSize = DeclaredSize;
        }

        public SessionSetupRequest(byte[] buffer, int offset) : base(buffer, offset)
        {
            StructureSize = LittleEndianConverter.ToUInt16(buffer, offset + SMB2Header.Length + 0);
            Flags = (SessionSetupFlags) ByteReader.ReadByte(buffer, offset + SMB2Header.Length + 2);
            SecurityMode = (SecurityMode) ByteReader.ReadByte(buffer, offset + SMB2Header.Length + 3);
            Capabilities = (Capabilities) LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 4);
            Channel = LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 8);
            SecurityBufferOffset = LittleEndianConverter.ToUInt16(buffer, offset + SMB2Header.Length + 12);
            SecurityBufferLength = LittleEndianConverter.ToUInt16(buffer, offset + SMB2Header.Length + 14);
            PreviousSessionId = LittleEndianConverter.ToUInt64(buffer, offset + SMB2Header.Length + 16);
            if (SecurityBufferLength > 0)
                SecurityBuffer = ByteReader.ReadBytes(buffer, offset + SecurityBufferOffset, SecurityBufferLength);
        }

        public override int CommandLength => FixedSize + SecurityBuffer.Length;

        public override void WriteCommandBytes(byte[] buffer, int offset)
        {
            SecurityBufferOffset = 0;
            SecurityBufferLength = (ushort) SecurityBuffer.Length;
            if (SecurityBuffer.Length > 0) SecurityBufferOffset = SMB2Header.Length + FixedSize;
            LittleEndianWriter.WriteUInt16(buffer, offset + 0, StructureSize);
            ByteWriter.WriteByte(buffer, offset + 2, (byte) Flags);
            ByteWriter.WriteByte(buffer, offset + 3, (byte) SecurityMode);
            LittleEndianWriter.WriteUInt32(buffer, offset + 4, (uint) Capabilities);
            LittleEndianWriter.WriteUInt32(buffer, offset + 8, Channel);
            LittleEndianWriter.WriteUInt16(buffer, offset + 12, SecurityBufferOffset);
            LittleEndianWriter.WriteUInt16(buffer, offset + 14, SecurityBufferLength);
            LittleEndianWriter.WriteUInt64(buffer, offset + 16, PreviousSessionId);
            ByteWriter.WriteBytes(buffer, offset + FixedSize, SecurityBuffer);
        }
    }
}