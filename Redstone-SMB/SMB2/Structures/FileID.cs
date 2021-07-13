/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using LittleEndianConverter = RedstoneSmb.Utilities.Conversion.LittleEndianConverter;
using LittleEndianWriter = RedstoneSmb.Utilities.ByteUtils.LittleEndianWriter;

namespace RedstoneSmb.SMB2.Structures
{
    /// <summary>
    ///     [MS-SMB2] 2.2.14.1 - SMB2_FILEID
    /// </summary>
    public struct FileId
    {
        public const int Length = 16;

        public ulong Persistent;
        public ulong Volatile;

        public FileId(byte[] buffer, int offset)
        {
            Persistent = LittleEndianConverter.ToUInt64(buffer, offset + 0);
            Volatile = LittleEndianConverter.ToUInt64(buffer, offset + 8);
        }

        public void WriteBytes(byte[] buffer, int offset)
        {
            LittleEndianWriter.WriteUInt64(buffer, offset + 0, Persistent);
            LittleEndianWriter.WriteUInt64(buffer, offset + 8, Volatile);
        }
    }
}