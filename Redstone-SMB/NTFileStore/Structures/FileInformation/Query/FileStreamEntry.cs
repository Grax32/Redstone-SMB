/* Copyright (C) 2017-2018 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using ByteReader = RedstoneSmb.Utilities.ByteUtils.ByteReader;
using ByteWriter = RedstoneSmb.Utilities.ByteUtils.ByteWriter;
using LittleEndianConverter = RedstoneSmb.Utilities.Conversion.LittleEndianConverter;
using LittleEndianWriter = RedstoneSmb.Utilities.ByteUtils.LittleEndianWriter;

namespace RedstoneSmb.NTFileStore.Structures.FileInformation.Query
{
    /// <summary>
    ///     [MS-FSCC] 2.4.40 - FileStreamInformation data element
    /// </summary>
    public class FileStreamEntry
    {
        public const int FixedLength = 24;

        public uint NextEntryOffset;
        public long StreamAllocationSize;
        public string StreamName = string.Empty;
        private uint _streamNameLength;
        public long StreamSize;

        public FileStreamEntry()
        {
        }

        public FileStreamEntry(byte[] buffer, int offset)
        {
            NextEntryOffset = LittleEndianConverter.ToUInt32(buffer, offset + 0);
            _streamNameLength = LittleEndianConverter.ToUInt32(buffer, offset + 4);
            StreamSize = LittleEndianConverter.ToInt64(buffer, offset + 8);
            StreamAllocationSize = LittleEndianConverter.ToInt64(buffer, offset + 16);
            StreamName = ByteReader.ReadUtf16String(buffer, offset + 24, (int) _streamNameLength / 2);
        }

        public int Length => FixedLength + StreamName.Length * 2;

        /// <summary>
        ///     [MS-FSCC] When multiple FILE_STREAM_INFORMATION data elements are present in the buffer, each MUST be aligned on an
        ///     8-byte boundary
        /// </summary>
        public int PaddedLength
        {
            get
            {
                var length = Length;
                var padding = (8 - length % 8) % 8;
                return length + padding;
            }
        }

        public void WriteBytes(byte[] buffer, int offset)
        {
            _streamNameLength = (uint) (StreamName.Length * 2);
            LittleEndianWriter.WriteUInt32(buffer, offset + 0, NextEntryOffset);
            LittleEndianWriter.WriteUInt32(buffer, offset + 4, _streamNameLength);
            LittleEndianWriter.WriteInt64(buffer, offset + 8, StreamSize);
            LittleEndianWriter.WriteInt64(buffer, offset + 16, StreamAllocationSize);
            ByteWriter.WriteUtf16String(buffer, offset + 24, StreamName);
        }
    }
}