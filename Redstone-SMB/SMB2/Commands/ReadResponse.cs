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
    ///     SMB2 READ Response
    /// </summary>
    public class ReadResponse : Smb2Command
    {
        public const int FixedSize = 16;
        public const int DeclaredSize = 17;
        public byte[] Data = new byte[0];
        private uint _dataLength;
        private byte _dataOffset;
        public uint DataRemaining;
        public byte Reserved;
        public uint Reserved2;

        private readonly ushort _structureSize;

        public ReadResponse() : base(Smb2CommandName.Read)
        {
            Header.IsResponse = true;
            _structureSize = DeclaredSize;
        }

        public ReadResponse(byte[] buffer, int offset) : base(buffer, offset)
        {
            _structureSize = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 0);
            _dataOffset = ByteReader.ReadByte(buffer, offset + Smb2Header.Length + 2);
            Reserved = ByteReader.ReadByte(buffer, offset + Smb2Header.Length + 3);
            _dataLength = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 4);
            DataRemaining = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 8);
            Reserved2 = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 12);
            if (_dataLength > 0) Data = ByteReader.ReadBytes(buffer, offset + _dataOffset, (int) _dataLength);
        }

        public override int CommandLength => FixedSize + Data.Length;

        public override void WriteCommandBytes(byte[] buffer, int offset)
        {
            _dataOffset = 0;
            _dataLength = (uint) Data.Length;
            if (Data.Length > 0) _dataOffset = Smb2Header.Length + FixedSize;
            LittleEndianWriter.WriteUInt16(buffer, offset + 0, _structureSize);
            ByteWriter.WriteByte(buffer, offset + 2, _dataOffset);
            ByteWriter.WriteByte(buffer, offset + 3, Reserved);
            LittleEndianWriter.WriteUInt32(buffer, offset + 4, _dataLength);
            LittleEndianWriter.WriteUInt32(buffer, offset + 8, DataRemaining);
            LittleEndianWriter.WriteUInt32(buffer, offset + 12, Reserved2);
            if (Data.Length > 0) ByteWriter.WriteBytes(buffer, offset + FixedSize, Data);
        }
    }
}