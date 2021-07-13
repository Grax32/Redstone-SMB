/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using RedstoneSmb.NTFileStore.Enums.FileInformation;
using ByteReader = RedstoneSmb.Utilities.ByteUtils.ByteReader;
using ByteWriter = RedstoneSmb.Utilities.ByteUtils.ByteWriter;
using Conversion = RedstoneSmb.Utilities.Conversion.Conversion;
using LittleEndianConverter = RedstoneSmb.Utilities.Conversion.LittleEndianConverter;
using LittleEndianWriter = RedstoneSmb.Utilities.ByteUtils.LittleEndianWriter;

namespace RedstoneSmb.NTFileStore.Structures.FileInformation.Set
{
    /// <summary>
    ///     [MS-FSCC] 2.4.21.2 - FileLinkInformation Type 2
    /// </summary>
    /// <remarks>
    ///     [MS-FSA] 2.1.5.14.6
    ///     FILE_LINK_INFORMATION_TYPE_1: Used for 32-bit local clients and the SMB1 protocol.
    ///     FILE_LINK_INFORMATION_TYPE_2: Used for 64-bit local clients and the SMB2 protocol.
    /// </remarks>
    public class FileLinkInformationType2 : FileInformation
    {
        public const int FixedLength = 20;
        public string FileName = string.Empty;
        private uint _fileNameLength;

        public bool ReplaceIfExists;

        // 7 reserved bytes
        public ulong RootDirectory;

        public FileLinkInformationType2()
        {
        }

        public FileLinkInformationType2(byte[] buffer, int offset)
        {
            ReplaceIfExists = Conversion.ToBoolean(ByteReader.ReadByte(buffer, offset + 0));
            RootDirectory = LittleEndianConverter.ToUInt64(buffer, offset + 8);
            _fileNameLength = LittleEndianConverter.ToUInt32(buffer, offset + 16);
            FileName = ByteReader.ReadUtf16String(buffer, offset + 20, (int) _fileNameLength / 2);
        }

        public override FileInformationClass FileInformationClass => FileInformationClass.FileLinkInformation;

        public override int Length => FixedLength + FileName.Length * 2;

        public override void WriteBytes(byte[] buffer, int offset)
        {
            _fileNameLength = (uint) (FileName.Length * 2);
            ByteWriter.WriteByte(buffer, offset + 0, Convert.ToByte(ReplaceIfExists));
            LittleEndianWriter.WriteUInt64(buffer, offset + 8, RootDirectory);
            LittleEndianWriter.WriteUInt32(buffer, offset + 16, _fileNameLength);
            ByteWriter.WriteUtf16String(buffer, offset + 20, FileName);
        }
    }
}