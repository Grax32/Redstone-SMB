/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using RedstoneSmb.SMB2.Enums;
using ByteReader = RedstoneSmb.Utilities.ByteUtils.ByteReader;
using ByteWriter = RedstoneSmb.Utilities.ByteUtils.ByteWriter;
using LittleEndianConverter = RedstoneSmb.Utilities.Conversion.LittleEndianConverter;
using LittleEndianWriter = RedstoneSmb.Utilities.ByteUtils.LittleEndianWriter;

namespace RedstoneSmb.SMB2.Commands
{
    /// <summary>
    ///     SMB2 WRITE Response
    /// </summary>
    public class WriteResponse : Smb2Command
    {
        public const int FixedSize = 16;
        public const int DeclaredSize = 17;
        public uint Count;
        public uint Remaining;
        public ushort Reserved;

        private readonly ushort _structureSize;
        public byte[] WriteChannelInfo = new byte[0];
        private ushort _writeChannelInfoLength;
        private ushort _writeChannelInfoOffset;

        public WriteResponse() : base(Smb2CommandName.Write)
        {
            Header.IsResponse = true;
            _structureSize = DeclaredSize;
        }

        public WriteResponse(byte[] buffer, int offset) : base(buffer, offset)
        {
            _structureSize = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 0);
            Reserved = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 2);
            Count = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 4);
            Remaining = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 8);
            _writeChannelInfoOffset = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 12);
            _writeChannelInfoLength = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 14);
            WriteChannelInfo = ByteReader.ReadBytes(buffer, offset + _writeChannelInfoOffset, _writeChannelInfoLength);
        }

        public override int CommandLength => FixedSize + WriteChannelInfo.Length;

        public override void WriteCommandBytes(byte[] buffer, int offset)
        {
            _writeChannelInfoOffset = 0;
            _writeChannelInfoLength = (ushort) WriteChannelInfo.Length;
            if (WriteChannelInfo.Length > 0) _writeChannelInfoOffset = Smb2Header.Length + FixedSize;
            LittleEndianWriter.WriteUInt16(buffer, offset + 0, _structureSize);
            LittleEndianWriter.WriteUInt16(buffer, offset + 2, Reserved);
            LittleEndianWriter.WriteUInt32(buffer, offset + 4, Count);
            LittleEndianWriter.WriteUInt32(buffer, offset + 8, Remaining);
            LittleEndianWriter.WriteUInt16(buffer, offset + 12, _writeChannelInfoOffset);
            LittleEndianWriter.WriteUInt16(buffer, offset + 14, _writeChannelInfoLength);
            if (WriteChannelInfo.Length > 0) ByteWriter.WriteBytes(buffer, offset + FixedSize, WriteChannelInfo);
        }
    }
}