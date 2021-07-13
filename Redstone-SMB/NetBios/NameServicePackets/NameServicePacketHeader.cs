/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.IO;
using RedstoneSmb.NetBios.NameServicePackets.Enums;
using BigEndianConverter = RedstoneSmb.Utilities.Conversion.BigEndianConverter;
using BigEndianWriter = RedstoneSmb.Utilities.ByteUtils.BigEndianWriter;

namespace RedstoneSmb.NetBios.NameServicePackets
{
    /// <summary>
    ///     [RFC 1002] 4.2.1.1. HEADER
    /// </summary>
    public class NameServicePacketHeader
    {
        public const int Length = 12;
        public ushort AnCount;
        public ushort ArCount;
        public OperationFlags Flags;
        public ushort NsCount;
        public NameServiceOperation OpCode;
        public ushort QdCount;
        public byte ResultCode;

        public ushort TransactionId;

        public NameServicePacketHeader()
        {
        }

        public NameServicePacketHeader(byte[] buffer, ref int offset) : this(buffer, offset)
        {
            offset += Length;
        }

        public NameServicePacketHeader(byte[] buffer, int offset)
        {
            TransactionId = BigEndianConverter.ToUInt16(buffer, offset + 0);
            var temp = BigEndianConverter.ToUInt16(buffer, offset + 2);
            ResultCode = (byte) (temp & 0xF);
            Flags = (OperationFlags) ((temp >> 4) & 0x7F);
            OpCode = (NameServiceOperation) ((temp >> 11) & 0x1F);
            QdCount = BigEndianConverter.ToUInt16(buffer, offset + 4);
            AnCount = BigEndianConverter.ToUInt16(buffer, offset + 6);
            NsCount = BigEndianConverter.ToUInt16(buffer, offset + 8);
            ArCount = BigEndianConverter.ToUInt16(buffer, offset + 10);
        }

        public void WriteBytes(Stream stream)
        {
            BigEndianWriter.WriteUInt16(stream, TransactionId);
            var temp = (ushort) (ResultCode & 0xF);
            temp |= (ushort) ((byte) Flags << 4);
            temp |= (ushort) ((byte) OpCode << 11);
            BigEndianWriter.WriteUInt16(stream, temp);
            BigEndianWriter.WriteUInt16(stream, QdCount);
            BigEndianWriter.WriteUInt16(stream, AnCount);
            BigEndianWriter.WriteUInt16(stream, NsCount);
            BigEndianWriter.WriteUInt16(stream, ArCount);
        }
    }
}