/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using RedstoneSmb.NTFileStore.Enums.FileSystemInformation;
using ByteReader = RedstoneSmb.Utilities.ByteUtils.ByteReader;
using ByteWriter = RedstoneSmb.Utilities.ByteUtils.ByteWriter;
using LittleEndianConverter = RedstoneSmb.Utilities.Conversion.LittleEndianConverter;
using LittleEndianWriter = RedstoneSmb.Utilities.ByteUtils.LittleEndianWriter;

namespace RedstoneSmb.NTFileStore.Structures.FileSystemInformation
{
    /// <summary>
    ///     [MS-FSCC] 2.5.6 - FileFsObjectIdInformation
    /// </summary>
    public class FileFsObjectIdInformation : FileSystemInformation
    {
        public const int FixedLength = 64;
        public byte[] ExtendedInfo; //48 bytes

        public Guid ObjectId;

        public FileFsObjectIdInformation()
        {
            ExtendedInfo = new byte[48];
        }

        public FileFsObjectIdInformation(byte[] buffer, int offset)
        {
            LittleEndianConverter.ToGuid(buffer, offset + 0);
            ExtendedInfo = ByteReader.ReadBytes(buffer, offset + 16, 48);
        }

        public override FileSystemInformationClass FileSystemInformationClass =>
            FileSystemInformationClass.FileFsObjectIdInformation;

        public override int Length => FixedLength;

        public override void WriteBytes(byte[] buffer, int offset)
        {
            LittleEndianWriter.WriteGuid(buffer, offset + 0, ObjectId);
            ByteWriter.WriteBytes(buffer, offset + 16, ExtendedInfo);
        }
    }
}