/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using RedstoneSmb.Helpers;
using RedstoneSmb.NTFileStore.Enums.FileSystemInformation;
using ByteReader = RedstoneSmb.Utilities.ByteUtils.ByteReader;
using ByteWriter = RedstoneSmb.Utilities.ByteUtils.ByteWriter;
using LittleEndianConverter = RedstoneSmb.Utilities.Conversion.LittleEndianConverter;
using LittleEndianWriter = RedstoneSmb.Utilities.ByteUtils.LittleEndianWriter;

namespace RedstoneSmb.NTFileStore.Structures.FileSystemInformation
{
    /// <summary>
    ///     [MS-FSCC] 2.5.9 - FileFsVolumeInformation
    /// </summary>
    public class FileFsVolumeInformation : FileSystemInformation
    {
        public const int FixedLength = 18;
        public byte Reserved;
        public bool SupportsObjects;

        public DateTime? VolumeCreationTime;
        public string VolumeLabel = string.Empty;
        private uint _volumeLabelLength;
        public uint VolumeSerialNumber;

        public FileFsVolumeInformation()
        {
        }

        public FileFsVolumeInformation(byte[] buffer, int offset)
        {
            VolumeCreationTime = FileTimeHelper.ReadNullableFileTime(buffer, offset + 0);
            VolumeSerialNumber = LittleEndianConverter.ToUInt32(buffer, offset + 8);
            _volumeLabelLength = LittleEndianConverter.ToUInt32(buffer, offset + 12);
            SupportsObjects = Convert.ToBoolean(ByteReader.ReadByte(buffer, offset + 16));
            Reserved = ByteReader.ReadByte(buffer, offset + 17);
            if (_volumeLabelLength > 0)
                VolumeLabel = ByteReader.ReadUtf16String(buffer, offset + 18, (int) _volumeLabelLength / 2);
        }

        public override FileSystemInformationClass FileSystemInformationClass =>
            FileSystemInformationClass.FileFsVolumeInformation;

        public override int Length => FixedLength + VolumeLabel.Length * 2;

        public override void WriteBytes(byte[] buffer, int offset)
        {
            _volumeLabelLength = (uint) (VolumeLabel.Length * 2);
            FileTimeHelper.WriteFileTime(buffer, offset + 0, VolumeCreationTime);
            LittleEndianWriter.WriteUInt32(buffer, offset + 8, VolumeSerialNumber);
            LittleEndianWriter.WriteUInt32(buffer, offset + 12, _volumeLabelLength);
            ByteWriter.WriteByte(buffer, offset + 16, Convert.ToByte(SupportsObjects));
            ByteWriter.WriteByte(buffer, offset + 17, Reserved);
            ByteWriter.WriteUtf16String(buffer, offset + 18, VolumeLabel);
        }
    }
}