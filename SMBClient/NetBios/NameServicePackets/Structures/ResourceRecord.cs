/* Copyright (C) 2014-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.IO;
using SMBLibrary.NetBios.NameServicePackets.Enums;
using SMBLibrary.Utilities.ByteUtils;
using BigEndianReader = SMBLibrary.Utilities.ByteUtils.BigEndianReader;
using BigEndianWriter = SMBLibrary.Utilities.ByteUtils.BigEndianWriter;
using ByteReader = SMBLibrary.Utilities.ByteUtils.ByteReader;
using ByteWriter = SMBLibrary.Utilities.ByteUtils.ByteWriter;

namespace SMBLibrary.NetBios.NameServicePackets.Structures
{
    /// <summary>
    ///     [RFC 1002] 4.2.1.3. RESOURCE RECORD
    /// </summary>
    public class ResourceRecord
    {
        public ResourceRecordClass Class;

        // ushort DataLength
        public byte[] Data;
        public string Name;
        public uint TTL;
        public NameRecordType Type;

        public ResourceRecord(NameRecordType type)
        {
            Name = string.Empty;
            Type = type;
            Class = ResourceRecordClass.In;
            TTL = (uint) new TimeSpan(7, 0, 0, 0).TotalSeconds;
            Data = new byte[0];
        }

        public ResourceRecord(byte[] buffer, ref int offset)
        {
            Name = NetBiosUtils.DecodeName(buffer, ref offset);
            Type = (NameRecordType) BigEndianReader.ReadUInt16(buffer, ref offset);
            Class = (ResourceRecordClass) BigEndianReader.ReadUInt16(buffer, ref offset);
            TTL = BigEndianReader.ReadUInt32(buffer, ref offset);
            var dataLength = BigEndianReader.ReadUInt16(buffer, ref offset);
            Data = ByteReader.ReadBytes(buffer, ref offset, dataLength);
        }

        public void WriteBytes(Stream stream)
        {
            WriteBytes(stream, null);
        }

        public void WriteBytes(Stream stream, int? nameOffset)
        {
            if (nameOffset.HasValue)
            {
                NetBiosUtils.WriteNamePointer(stream, nameOffset.Value);
            }
            else
            {
                var encodedName = NetBiosUtils.EncodeName(Name, string.Empty);
                ByteWriter.WriteBytes(stream, encodedName);
            }

            BigEndianWriter.WriteUInt16(stream, (ushort) Type);
            BigEndianWriter.WriteUInt16(stream, (ushort) Class);
            BigEndianWriter.WriteUInt32(stream, TTL);
            BigEndianWriter.WriteUInt16(stream, (ushort) Data.Length);
            ByteWriter.WriteBytes(stream, Data);
        }
    }
}