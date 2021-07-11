/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.NTFileStore.Enums.FileSystemInformation;
using SMBLibrary.Utilities.ByteUtils;
using SMBLibrary.Utilities.Conversion;
using LittleEndianConverter = SMBLibrary.Utilities.Conversion.LittleEndianConverter;
using LittleEndianWriter = SMBLibrary.Utilities.ByteUtils.LittleEndianWriter;

namespace SMBLibrary.NTFileStore.Structures.FileSystemInformation
{
    /// <summary>
    ///     [MS-FSCC] 2.5.2 - FileFsControlInformation
    /// </summary>
    public class FileFsControlInformation : FileSystemInformation
    {
        public const int FixedLength = 48;
        public ulong DefaultQuotaLimit;
        public ulong DefaultQuotaThreshold;
        public FileSystemControlFlags FileSystemControlFlags;

        public long FreeSpaceStartFiltering;
        public long FreeSpaceStopFiltering;
        public long FreeSpaceThreshold;
        public uint Padding;

        public FileFsControlInformation()
        {
        }

        public FileFsControlInformation(byte[] buffer, int offset)
        {
            FreeSpaceStartFiltering = LittleEndianConverter.ToInt64(buffer, offset + 0);
            FreeSpaceThreshold = LittleEndianConverter.ToInt64(buffer, offset + 8);
            FreeSpaceStopFiltering = LittleEndianConverter.ToInt64(buffer, offset + 16);
            DefaultQuotaThreshold = LittleEndianConverter.ToUInt64(buffer, offset + 24);
            DefaultQuotaLimit = LittleEndianConverter.ToUInt64(buffer, offset + 32);
            FileSystemControlFlags = (FileSystemControlFlags) LittleEndianConverter.ToUInt32(buffer, offset + 40);
            Padding = LittleEndianConverter.ToUInt32(buffer, offset + 44);
        }

        public override FileSystemInformationClass FileSystemInformationClass =>
            FileSystemInformationClass.FileFsControlInformation;

        public override int Length => FixedLength;

        public override void WriteBytes(byte[] buffer, int offset)
        {
            LittleEndianWriter.WriteInt64(buffer, offset + 0, FreeSpaceStartFiltering);
            LittleEndianWriter.WriteInt64(buffer, offset + 8, FreeSpaceThreshold);
            LittleEndianWriter.WriteInt64(buffer, offset + 16, FreeSpaceStopFiltering);
            LittleEndianWriter.WriteUInt64(buffer, offset + 24, DefaultQuotaThreshold);
            LittleEndianWriter.WriteUInt64(buffer, offset + 32, DefaultQuotaLimit);
            LittleEndianWriter.WriteUInt32(buffer, offset + 40, (uint) FileSystemControlFlags);
            LittleEndianWriter.WriteUInt32(buffer, offset + 44, Padding);
        }
    }
}