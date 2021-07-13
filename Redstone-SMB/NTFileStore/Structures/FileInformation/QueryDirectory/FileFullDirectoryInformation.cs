/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using RedstoneSmb.NTFileStore.Enums.FileInformation;
using ByteReader = RedstoneSmb.Utilities.ByteUtils.ByteReader;
using ByteWriter = RedstoneSmb.Utilities.ByteUtils.ByteWriter;
using LittleEndianConverter = RedstoneSmb.Utilities.Conversion.LittleEndianConverter;
using LittleEndianWriter = RedstoneSmb.Utilities.ByteUtils.LittleEndianWriter;

namespace RedstoneSmb.NTFileStore.Structures.FileInformation.QueryDirectory
{
    /// <summary>
    ///     [MS-FSCC] 2.4.14 - FileFullDirectoryInformation
    /// </summary>
    public class FileFullDirectoryInformation : QueryDirectoryFileInformation
    {
        public const int FixedLength = 68;
        public long AllocationSize;
        public DateTime ChangeTime;

        public DateTime CreationTime;
        public uint EaSize;
        public long EndOfFile;
        public FileAttributes FileAttributes;
        public string FileName = string.Empty;
        private uint _fileNameLength;
        public DateTime LastAccessTime;
        public DateTime LastWriteTime;

        public FileFullDirectoryInformation()
        {
        }

        public FileFullDirectoryInformation(byte[] buffer, int offset) : base(buffer, offset)
        {
            CreationTime = DateTime.FromFileTimeUtc(LittleEndianConverter.ToInt64(buffer, offset + 8));
            LastAccessTime = DateTime.FromFileTimeUtc(LittleEndianConverter.ToInt64(buffer, offset + 16));
            LastWriteTime = DateTime.FromFileTimeUtc(LittleEndianConverter.ToInt64(buffer, offset + 24));
            ChangeTime = DateTime.FromFileTimeUtc(LittleEndianConverter.ToInt64(buffer, offset + 32));
            EndOfFile = LittleEndianConverter.ToInt64(buffer, offset + 40);
            AllocationSize = LittleEndianConverter.ToInt64(buffer, offset + 48);
            FileAttributes = (FileAttributes) LittleEndianConverter.ToUInt32(buffer, offset + 56);
            _fileNameLength = LittleEndianConverter.ToUInt32(buffer, offset + 60);
            EaSize = LittleEndianConverter.ToUInt32(buffer, offset + 64);
            FileName = ByteReader.ReadUtf16String(buffer, offset + 68, (int) _fileNameLength / 2);
        }

        public override FileInformationClass FileInformationClass => FileInformationClass.FileFullDirectoryInformation;

        public override int Length => FixedLength + FileName.Length * 2;

        public override void WriteBytes(byte[] buffer, int offset)
        {
            base.WriteBytes(buffer, offset);
            _fileNameLength = (uint) (FileName.Length * 2);
            LittleEndianWriter.WriteInt64(buffer, offset + 8, CreationTime.ToFileTimeUtc());
            LittleEndianWriter.WriteInt64(buffer, offset + 16, LastAccessTime.ToFileTimeUtc());
            LittleEndianWriter.WriteInt64(buffer, offset + 24, LastWriteTime.ToFileTimeUtc());
            LittleEndianWriter.WriteInt64(buffer, offset + 32, ChangeTime.ToFileTimeUtc());
            LittleEndianWriter.WriteInt64(buffer, offset + 40, EndOfFile);
            LittleEndianWriter.WriteInt64(buffer, offset + 48, AllocationSize);
            LittleEndianWriter.WriteUInt32(buffer, offset + 56, (uint) FileAttributes);
            LittleEndianWriter.WriteUInt32(buffer, offset + 60, _fileNameLength);
            LittleEndianWriter.WriteUInt32(buffer, offset + 64, EaSize);
            ByteWriter.WriteUtf16String(buffer, offset + 68, FileName);
        }
    }
}