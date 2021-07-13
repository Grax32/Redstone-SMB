/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using RedstoneSmb.NTFileStore.Enums.FileSystemInformation;
using ByteReader = RedstoneSmb.Utilities.ByteUtils.ByteReader;
using ByteWriter = RedstoneSmb.Utilities.ByteUtils.ByteWriter;
using LittleEndianConverter = RedstoneSmb.Utilities.Conversion.LittleEndianConverter;
using LittleEndianWriter = RedstoneSmb.Utilities.ByteUtils.LittleEndianWriter;

namespace RedstoneSmb.NTFileStore.Structures.FileSystemInformation
{
    /// <summary>
    ///     [MS-FSCC] 2.5.1 - FileFsAttributeInformation
    /// </summary>
    public class FileFsAttributeInformation : FileSystemInformation
    {
        public const int FixedLength = 12;

        public FileSystemAttributes FileSystemAttributes;
        public string FileSystemName = string.Empty;
        private uint _fileSystemNameLength;

        /// <summary>
        ///     Maximum file name component length, in bytes, supported by the specified file system.
        ///     The value of this field MUST be greater than zero and MUST be no more than 510.
        /// </summary>
        public uint MaximumComponentNameLength;

        public FileFsAttributeInformation()
        {
        }

        public FileFsAttributeInformation(byte[] buffer, int offset)
        {
            FileSystemAttributes = (FileSystemAttributes) LittleEndianConverter.ToUInt32(buffer, offset + 0);
            MaximumComponentNameLength = LittleEndianConverter.ToUInt32(buffer, offset + 4);
            _fileSystemNameLength = LittleEndianConverter.ToUInt32(buffer, offset + 8);
            FileSystemName = ByteReader.ReadUtf16String(buffer, offset + 12, (int) _fileSystemNameLength / 2);
        }

        public override FileSystemInformationClass FileSystemInformationClass =>
            FileSystemInformationClass.FileFsAttributeInformation;

        public override int Length => FixedLength + FileSystemName.Length * 2;

        public override void WriteBytes(byte[] buffer, int offset)
        {
            _fileSystemNameLength = (uint) (FileSystemName.Length * 2);
            LittleEndianWriter.WriteUInt32(buffer, offset + 0, (uint) FileSystemAttributes);
            LittleEndianWriter.WriteUInt32(buffer, offset + 4, MaximumComponentNameLength);
            LittleEndianWriter.WriteUInt32(buffer, offset + 8, _fileSystemNameLength);
            ByteWriter.WriteUtf16String(buffer, offset + 12, FileSystemName);
        }
    }
}