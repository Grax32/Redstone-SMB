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

namespace RedstoneSmb.NTFileStore.Structures.FileInformation.QueryDirectory
{
    /// <summary>
    ///     [MS-FSCC] 2.4.26 - FileNamesInformation
    /// </summary>
    public class FileNamesInformation : QueryDirectoryFileInformation
    {
        public const int FixedLength = 12;
        public string FileName = string.Empty;

        private uint _fileNameLength;

        public FileNamesInformation()
        {
        }

        public FileNamesInformation(byte[] buffer, int offset) : base(buffer, offset)
        {
            _fileNameLength = LittleEndianConverter.ToUInt32(buffer, offset + 8);
            FileName = ByteReader.ReadUtf16String(buffer, offset + 12, (int) _fileNameLength / 2);
        }

        public override FileInformationClass FileInformationClass => FileInformationClass.FileNamesInformation;

        public override int Length => FixedLength + FileName.Length * 2;

        public override void WriteBytes(byte[] buffer, int offset)
        {
            base.WriteBytes(buffer, offset);
            _fileNameLength = (uint) (FileName.Length * 2);
            LittleEndianWriter.WriteUInt32(buffer, offset + 8, _fileNameLength);
            ByteWriter.WriteUtf16String(buffer, offset + 12, FileName);
        }
    }
}