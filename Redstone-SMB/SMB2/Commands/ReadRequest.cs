/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using RedstoneSmb.SMB2.Enums;
using RedstoneSmb.SMB2.Enums.Read;
using RedstoneSmb.SMB2.Structures;
using ByteReader = RedstoneSmb.Utilities.ByteUtils.ByteReader;
using ByteWriter = RedstoneSmb.Utilities.ByteUtils.ByteWriter;
using LittleEndianConverter = RedstoneSmb.Utilities.Conversion.LittleEndianConverter;
using LittleEndianWriter = RedstoneSmb.Utilities.ByteUtils.LittleEndianWriter;

namespace RedstoneSmb.SMB2.Commands
{
    /// <summary>
    ///     SMB2 READ Request
    /// </summary>
    public class ReadRequest : Smb2Command
    {
        public const int FixedSize = 48;
        public const int DeclaredSize = 49;
        public uint Channel;
        public FileId FileId;
        public ReadFlags Flags;
        public uint MinimumCount;
        public ulong Offset;
        public byte Padding;
        public byte[] ReadChannelInfo = new byte[0];
        private ushort _readChannelInfoLength;
        private ushort _readChannelInfoOffset;
        public uint ReadLength;
        public uint RemainingBytes;

        private readonly ushort _structureSize;

        public ReadRequest() : base(Smb2CommandName.Read)
        {
            _structureSize = DeclaredSize;
        }

        public ReadRequest(byte[] buffer, int offset) : base(buffer, offset)
        {
            _structureSize = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 0);
            Padding = ByteReader.ReadByte(buffer, offset + Smb2Header.Length + 2);
            Flags = (ReadFlags) ByteReader.ReadByte(buffer, offset + Smb2Header.Length + 3);
            ReadLength = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 4);
            Offset = LittleEndianConverter.ToUInt64(buffer, offset + Smb2Header.Length + 8);
            FileId = new FileId(buffer, offset + Smb2Header.Length + 16);
            MinimumCount = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 32);
            Channel = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 36);
            RemainingBytes = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 40);
            _readChannelInfoOffset = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 44);
            _readChannelInfoLength = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 46);
            if (_readChannelInfoLength > 0)
                ReadChannelInfo = ByteReader.ReadBytes(buffer, offset + _readChannelInfoOffset, _readChannelInfoLength);
        }

        public override int CommandLength =>
            // The client MUST set one byte of [the buffer] field to 0
            Math.Max(FixedSize + ReadChannelInfo.Length, DeclaredSize);

        public override void WriteCommandBytes(byte[] buffer, int offset)
        {
            _readChannelInfoOffset = 0;
            _readChannelInfoLength = (ushort) ReadChannelInfo.Length;
            if (ReadChannelInfo.Length > 0) _readChannelInfoOffset = Smb2Header.Length + FixedSize;
            LittleEndianWriter.WriteUInt16(buffer, offset + 0, _structureSize);
            ByteWriter.WriteByte(buffer, offset + 2, Padding);
            ByteWriter.WriteByte(buffer, offset + 3, (byte) Flags);
            LittleEndianWriter.WriteUInt32(buffer, offset + 4, ReadLength);
            LittleEndianWriter.WriteUInt64(buffer, offset + 8, Offset);
            FileId.WriteBytes(buffer, offset + 16);
            LittleEndianWriter.WriteUInt32(buffer, offset + 32, MinimumCount);
            LittleEndianWriter.WriteUInt32(buffer, offset + 36, Channel);
            LittleEndianWriter.WriteUInt32(buffer, offset + 40, RemainingBytes);
            LittleEndianWriter.WriteUInt16(buffer, offset + 44, _readChannelInfoOffset);
            LittleEndianWriter.WriteUInt16(buffer, offset + 46, _readChannelInfoLength);
            if (ReadChannelInfo.Length > 0)
                ByteWriter.WriteBytes(buffer, offset + FixedSize, ReadChannelInfo);
            else
                // The client MUST set one byte of [the buffer] field to 0
                ByteWriter.WriteBytes(buffer, offset + FixedSize, new byte[1]);
        }
    }
}