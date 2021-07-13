/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using RedstoneSmb.NTFileStore.Enums.FileInformation;
using ByteReader = RedstoneSmb.Utilities.ByteUtils.ByteReader;
using ByteWriter = RedstoneSmb.Utilities.ByteUtils.ByteWriter;
using LittleEndianReader = RedstoneSmb.Utilities.ByteUtils.LittleEndianReader;
using LittleEndianWriter = RedstoneSmb.Utilities.ByteUtils.LittleEndianWriter;

namespace RedstoneSmb.NTFileStore.Structures.FileInformation.Query
{
    /// <summary>
    ///     [MS-FSCC] 2.4.15 - FileFullEaInformation data element
    /// </summary>
    public class FileFullEaEntry
    {
        public const int FixedLength = 8;
        public string EaName; // 8-bit ASCII followed by a single terminating null character byte
        private byte _eaNameLength;
        public string EaValue; // 8-bit ASCII
        private ushort _eaValueLength;
        public ExtendedAttributeFlags Flags;

        public uint NextEntryOffset;

        public FileFullEaEntry()
        {
        }

        public FileFullEaEntry(byte[] buffer, int offset)
        {
            NextEntryOffset = LittleEndianReader.ReadUInt32(buffer, ref offset);
            Flags = (ExtendedAttributeFlags) ByteReader.ReadByte(buffer, ref offset);
            _eaNameLength = ByteReader.ReadByte(buffer, ref offset);
            _eaValueLength = LittleEndianReader.ReadUInt16(buffer, ref offset);
            EaName = ByteReader.ReadAnsiString(buffer, ref offset, _eaNameLength);
            offset++; // terminating null
            EaValue = ByteReader.ReadAnsiString(buffer, ref offset, _eaValueLength);
        }

        public int Length => FixedLength + EaName.Length + 1 + EaValue.Length;

        public void WriteBytes(byte[] buffer, int offset)
        {
            _eaNameLength = (byte) EaName.Length;
            _eaValueLength = (ushort) EaValue.Length;
            LittleEndianWriter.WriteUInt32(buffer, ref offset, NextEntryOffset);
            ByteWriter.WriteByte(buffer, ref offset, (byte) Flags);
            ByteWriter.WriteByte(buffer, ref offset, _eaNameLength);
            LittleEndianWriter.WriteUInt16(buffer, ref offset, _eaValueLength);
            ByteWriter.WriteAnsiString(buffer, ref offset, EaName);
            ByteWriter.WriteByte(buffer, ref offset, 0); // terminating null
            ByteWriter.WriteAnsiString(buffer, ref offset, EaValue);
        }
    }
}