/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using RedstoneSmb.NTFileStore.Enums.FileInformation;
using ByteReader = RedstoneSmb.Utilities.ByteUtils.ByteReader;
using ByteWriter = RedstoneSmb.Utilities.ByteUtils.ByteWriter;
using LittleEndianConverter = RedstoneSmb.Utilities.Conversion.LittleEndianConverter;
using LittleEndianWriter = RedstoneSmb.Utilities.ByteUtils.LittleEndianWriter;

namespace RedstoneSmb.NTFileStore.Structures.FileInformation.Query
{
    /// <summary>
    ///     [MS-FSCC] 2.1.7 - FILE_NAME_INFORMATION
    ///     [MS-FSCC] 2.4.25 - FileNameInformation
    /// </summary>
    public class FileNameInformation : FileInformation
    {
        public const int FixedLength = 4;
        public string FileName = string.Empty;

        private uint _fileNameLength;

        public FileNameInformation()
        {
        }

        public FileNameInformation(byte[] buffer, int offset)
        {
            _fileNameLength = LittleEndianConverter.ToUInt32(buffer, offset + 0);
            FileName = ByteReader.ReadUtf16String(buffer, offset + 4, (int) _fileNameLength / 2);
        }

        public override FileInformationClass FileInformationClass => FileInformationClass.FileNameInformation;

        public override int Length => FixedLength + FileName.Length * 2;

        public override void WriteBytes(byte[] buffer, int offset)
        {
            _fileNameLength = (uint) (FileName.Length * 2);
            LittleEndianWriter.WriteUInt32(buffer, offset + 0, _fileNameLength);
            ByteWriter.WriteUtf16String(buffer, offset + 4, FileName);
        }
    }
}