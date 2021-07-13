/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using ByteReader = RedstoneSmb.Utilities.ByteUtils.ByteReader;
using ByteWriter = RedstoneSmb.Utilities.ByteUtils.ByteWriter;
using LittleEndianConverter = RedstoneSmb.Utilities.Conversion.LittleEndianConverter;
using LittleEndianWriter = RedstoneSmb.Utilities.ByteUtils.LittleEndianWriter;

namespace RedstoneSmb.NTFileStore.Structures.IOCtl
{
    /// <summary>
    ///     [MS-FSCC] 2.3.31 - FSCTL_PIPE_WAIT Request
    /// </summary>
    public class PipeWaitRequest
    {
        public const int FixedLength = 14;
        public string Name;
        private readonly uint _nameLength;
        public byte Padding;

        public ulong Timeout;
        public bool TimeSpecified;

        public PipeWaitRequest()
        {
        }

        public PipeWaitRequest(byte[] buffer, int offset)
        {
            Timeout = LittleEndianConverter.ToUInt64(buffer, offset + 0);
            _nameLength = LittleEndianConverter.ToUInt32(buffer, offset + 8);
            TimeSpecified = Convert.ToBoolean(ByteReader.ReadByte(buffer, offset + 12));
            Padding = ByteReader.ReadByte(buffer, offset + 13);
            Name = ByteReader.ReadUtf16String(buffer, offset + 14, (int) (_nameLength / 2));
        }

        public int Length => FixedLength + Name.Length * 2;

        public byte[] GetBytes()
        {
            var buffer = new byte[Length];
            LittleEndianWriter.WriteUInt64(buffer, 0, Timeout);
            LittleEndianWriter.WriteUInt32(buffer, 8, (uint) (Name.Length * 2));
            ByteWriter.WriteByte(buffer, 12, Convert.ToByte(TimeSpecified));
            ByteWriter.WriteByte(buffer, 13, Padding);
            ByteWriter.WriteUtf16String(buffer, 14, Name);
            return buffer;
        }
    }
}