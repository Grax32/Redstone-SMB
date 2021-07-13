/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.Helpers;
using SMBLibrary.NTFileStore.Enums.FileInformation;
using SMBLibrary.NTFileStore.Structures.FileInformation.Set;
using SMBLibrary.Utilities.ByteUtils;
using SMBLibrary.Utilities.Conversion;
using LittleEndianConverter = SMBLibrary.Utilities.Conversion.LittleEndianConverter;
using LittleEndianWriter = SMBLibrary.Utilities.ByteUtils.LittleEndianWriter;

namespace SMBLibrary.NTFileStore.Structures.FileInformation.Query
{
    /// <summary>
    ///     [MS-FSCC] 2.4.7 - FileBasicInformation
    /// </summary>
    public class FileBasicInformation : FileInformation
    {
        public const int FixedLength = 40;
        public SetFileTime ChangeTime;

        public SetFileTime CreationTime;
        public FileAttributes FileAttributes;
        public SetFileTime LastAccessTime;
        public SetFileTime LastWriteTime;
        public uint Reserved;

        public FileBasicInformation()
        {
        }

        public FileBasicInformation(byte[] buffer, int offset)
        {
            CreationTime = FileTimeHelper.ReadSetFileTime(buffer, offset + 0);
            LastAccessTime = FileTimeHelper.ReadSetFileTime(buffer, offset + 8);
            LastWriteTime = FileTimeHelper.ReadSetFileTime(buffer, offset + 16);
            ChangeTime = FileTimeHelper.ReadSetFileTime(buffer, offset + 24);
            FileAttributes = (FileAttributes) LittleEndianConverter.ToUInt32(buffer, offset + 32);
            Reserved = LittleEndianConverter.ToUInt32(buffer, offset + 36);
        }

        public override FileInformationClass FileInformationClass => FileInformationClass.FileBasicInformation;

        public override int Length => FixedLength;

        public override void WriteBytes(byte[] buffer, int offset)
        {
            FileTimeHelper.WriteSetFileTime(buffer, offset + 0, CreationTime);
            FileTimeHelper.WriteSetFileTime(buffer, offset + 8, LastAccessTime);
            FileTimeHelper.WriteSetFileTime(buffer, offset + 16, LastWriteTime);
            FileTimeHelper.WriteSetFileTime(buffer, offset + 24, ChangeTime);
            LittleEndianWriter.WriteUInt32(buffer, offset + 32, (uint) FileAttributes);
            LittleEndianWriter.WriteUInt32(buffer, offset + 36, Reserved);
        }
    }
}