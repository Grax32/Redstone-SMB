/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using RedstoneSmb.NTFileStore.Enums.FileInformation;
using LittleEndianConverter = RedstoneSmb.Utilities.Conversion.LittleEndianConverter;
using LittleEndianWriter = RedstoneSmb.Utilities.ByteUtils.LittleEndianWriter;

namespace RedstoneSmb.NTFileStore.Structures.FileInformation.Set
{
    /// <summary>
    ///     [MS-FSCC] 2.4.4 - FileAllocationInformation
    /// </summary>
    public class FileAllocationInformation : FileInformation
    {
        public const int FixedLength = 8;

        public long AllocationSize;

        public FileAllocationInformation()
        {
        }

        public FileAllocationInformation(byte[] buffer, int offset)
        {
            AllocationSize = LittleEndianConverter.ToInt64(buffer, offset);
        }

        public override FileInformationClass FileInformationClass => FileInformationClass.FileAllocationInformation;

        public override int Length => FixedLength;

        public override void WriteBytes(byte[] buffer, int offset)
        {
            LittleEndianWriter.WriteInt64(buffer, offset, AllocationSize);
        }
    }
}