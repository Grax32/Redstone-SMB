/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using RedstoneSmb.SMB2.Enums;
using RedstoneSmb.SMB2.Enums.Write;
using RedstoneSmb.SMB2.Structures;
using ByteReader = RedstoneSmb.Utilities.ByteUtils.ByteReader;
using ByteWriter = RedstoneSmb.Utilities.ByteUtils.ByteWriter;
using LittleEndianConverter = RedstoneSmb.Utilities.Conversion.LittleEndianConverter;
using LittleEndianWriter = RedstoneSmb.Utilities.ByteUtils.LittleEndianWriter;

namespace RedstoneSmb.SMB2.Commands
{
    /// <summary>
    ///     SMB2 WRITE Request
    /// </summary>
    public class WriteRequest : Smb2Command
    {
        public const int FixedSize = 48;
        public const int DeclaredSize = 49;
        public uint Channel;
        public byte[] Data = new byte[0];
        private uint _dataLength;
        private ushort _dataOffset;
        public FileId FileId;
        public WriteFlags Flags;
        public ulong Offset;
        public uint RemainingBytes;

        private readonly ushort _structureSize;
        public byte[] WriteChannelInfo = new byte[0];
        private ushort _writeChannelInfoLength;
        private ushort _writeChannelInfoOffset;

        public WriteRequest() : base(Smb2CommandName.Write)
        {
            _structureSize = DeclaredSize;
        }

        public WriteRequest(byte[] buffer, int offset) : base(buffer, offset)
        {
            _structureSize = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 0);
            _dataOffset = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 2);
            _dataLength = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 4);
            Offset = LittleEndianConverter.ToUInt64(buffer, offset + Smb2Header.Length + 8);
            FileId = new FileId(buffer, offset + Smb2Header.Length + 16);
            Channel = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 32);
            RemainingBytes = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 36);
            _writeChannelInfoOffset = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 40);
            _writeChannelInfoLength = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 42);
            Flags = (WriteFlags) LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 44);
            Data = ByteReader.ReadBytes(buffer, offset + _dataOffset, (int) _dataLength);
            WriteChannelInfo = ByteReader.ReadBytes(buffer, offset + _writeChannelInfoOffset, _writeChannelInfoLength);
        }

        public override int CommandLength => FixedSize + Data.Length + WriteChannelInfo.Length;

        public override void WriteCommandBytes(byte[] buffer, int offset)
        {
            // Note: DataLength is UInt32 while WriteChannelInfoOffset is UInt16
            // so it is best to put WriteChannelInfo before Data.
            _writeChannelInfoOffset = 0;
            _writeChannelInfoLength = (ushort) WriteChannelInfo.Length;
            if (WriteChannelInfo.Length > 0) _writeChannelInfoOffset = Smb2Header.Length + FixedSize;
            _dataOffset = 0;
            _dataLength = (uint) Data.Length;
            if (Data.Length > 0) _dataOffset = (ushort) (Smb2Header.Length + FixedSize + WriteChannelInfo.Length);
            LittleEndianWriter.WriteUInt16(buffer, offset + 0, _structureSize);
            LittleEndianWriter.WriteUInt16(buffer, offset + 2, _dataOffset);
            LittleEndianWriter.WriteUInt32(buffer, offset + 4, _dataLength);
            LittleEndianWriter.WriteUInt64(buffer, offset + 8, Offset);
            FileId.WriteBytes(buffer, offset + 16);
            LittleEndianWriter.WriteUInt32(buffer, offset + 32, Channel);
            LittleEndianWriter.WriteUInt32(buffer, offset + 36, RemainingBytes);
            LittleEndianWriter.WriteUInt16(buffer, offset + 40, _writeChannelInfoOffset);
            LittleEndianWriter.WriteUInt16(buffer, offset + 42, _writeChannelInfoLength);
            LittleEndianWriter.WriteUInt32(buffer, offset + 44, (uint) Flags);
            if (WriteChannelInfo.Length > 0) ByteWriter.WriteBytes(buffer, offset + FixedSize, WriteChannelInfo);
            if (Data.Length > 0) ByteWriter.WriteBytes(buffer, offset + FixedSize + WriteChannelInfo.Length, Data);
        }
    }
}