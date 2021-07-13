/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using SMBLibrary.NTFileStore.Enums.FileInformation;
using SMBLibrary.Utilities.ByteUtils;
using SMBLibrary.Utilities.Conversion;
using ByteReader = SMBLibrary.Utilities.ByteUtils.ByteReader;
using ByteWriter = SMBLibrary.Utilities.ByteUtils.ByteWriter;
using LittleEndianConverter = SMBLibrary.Utilities.Conversion.LittleEndianConverter;
using LittleEndianWriter = SMBLibrary.Utilities.ByteUtils.LittleEndianWriter;

namespace SMBLibrary.NTFileStore.Structures.FileInformation.QueryDirectory
{
    /// <summary>
    ///     [MS-FSCC] 2.4.8 - FileBothDirectoryInformation
    /// </summary>
    public class FileBothDirectoryInformation : QueryDirectoryFileInformation
    {
        public const int FixedLength = 94;
        public long AllocationSize;
        public DateTime ChangeTime;

        public DateTime CreationTime;
        public uint EaSize;
        public long EndOfFile;
        public FileAttributes FileAttributes;
        public string FileName = string.Empty;
        private uint FileNameLength;
        public DateTime LastAccessTime;
        public DateTime LastWriteTime;
        public byte Reserved;
        public string ShortName = string.Empty; // Short (8.3) file name in UTF16 (24 bytes)
        private byte ShortNameLength;

        public FileBothDirectoryInformation()
        {
        }

        public FileBothDirectoryInformation(byte[] buffer, int offset) : base(buffer, offset)
        {
            CreationTime = DateTime.FromFileTimeUtc(LittleEndianConverter.ToInt64(buffer, offset + 8));
            LastAccessTime = DateTime.FromFileTimeUtc(LittleEndianConverter.ToInt64(buffer, offset + 16));
            LastWriteTime = DateTime.FromFileTimeUtc(LittleEndianConverter.ToInt64(buffer, offset + 24));
            ChangeTime = DateTime.FromFileTimeUtc(LittleEndianConverter.ToInt64(buffer, offset + 32));
            EndOfFile = LittleEndianConverter.ToInt64(buffer, offset + 40);
            AllocationSize = LittleEndianConverter.ToInt64(buffer, offset + 48);
            FileAttributes = (FileAttributes) LittleEndianConverter.ToUInt32(buffer, offset + 56);
            FileNameLength = LittleEndianConverter.ToUInt32(buffer, offset + 60);
            EaSize = LittleEndianConverter.ToUInt32(buffer, offset + 64);
            ShortNameLength = ByteReader.ReadByte(buffer, offset + 68);
            Reserved = ByteReader.ReadByte(buffer, offset + 69);
            ShortName = ByteReader.ReadUTF16String(buffer, offset + 70, ShortNameLength / 2);
            FileName = ByteReader.ReadUTF16String(buffer, offset + 94, (int) FileNameLength / 2);
        }

        public override FileInformationClass FileInformationClass => FileInformationClass.FileBothDirectoryInformation;

        public override int Length => FixedLength + FileName.Length * 2;

        public override void WriteBytes(byte[] buffer, int offset)
        {
            base.WriteBytes(buffer, offset);
            ShortNameLength = (byte) (ShortName.Length * 2);
            FileNameLength = (uint) (FileName.Length * 2);
            LittleEndianWriter.WriteInt64(buffer, offset + 8, CreationTime.ToFileTimeUtc());
            LittleEndianWriter.WriteInt64(buffer, offset + 16, LastAccessTime.ToFileTimeUtc());
            LittleEndianWriter.WriteInt64(buffer, offset + 24, LastWriteTime.ToFileTimeUtc());
            LittleEndianWriter.WriteInt64(buffer, offset + 32, ChangeTime.ToFileTimeUtc());
            LittleEndianWriter.WriteInt64(buffer, offset + 40, EndOfFile);
            LittleEndianWriter.WriteInt64(buffer, offset + 48, AllocationSize);
            LittleEndianWriter.WriteUInt32(buffer, offset + 56, (uint) FileAttributes);
            LittleEndianWriter.WriteUInt32(buffer, offset + 60, FileNameLength);
            LittleEndianWriter.WriteUInt32(buffer, offset + 64, EaSize);
            ByteWriter.WriteByte(buffer, offset + 68, ShortNameLength);
            ByteWriter.WriteByte(buffer, offset + 69, Reserved);
            ByteWriter.WriteUTF16String(buffer, offset + 70, ShortName);
            ByteWriter.WriteUTF16String(buffer, offset + 94, FileName);
        }
    }
}