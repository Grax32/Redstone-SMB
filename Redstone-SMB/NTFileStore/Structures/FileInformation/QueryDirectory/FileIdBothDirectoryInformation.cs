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
    ///     [MS-FSCC] 2.4.17 - FileIdBothDirectoryInformation
    /// </summary>
    public class FileIdBothDirectoryInformation : QueryDirectoryFileInformation
    {
        public const int FixedLength = 104;
        public long AllocationSize;
        public DateTime ChangeTime;

        public DateTime CreationTime;
        public uint EaSize;
        public long EndOfFile;
        public FileAttributes FileAttributes;
        public ulong FileId;
        public string FileName = string.Empty;
        private uint _fileNameLength;
        public DateTime LastAccessTime;
        public DateTime LastWriteTime;
        public byte Reserved1;
        public ushort Reserved2;
        public string ShortName = string.Empty; // Short (8.3) file name in UTF16 (24 bytes)
        private byte _shortNameLength;

        public FileIdBothDirectoryInformation()
        {
        }

        public FileIdBothDirectoryInformation(byte[] buffer, int offset) : base(buffer, offset)
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
            _shortNameLength = ByteReader.ReadByte(buffer, offset + 68);
            Reserved1 = ByteReader.ReadByte(buffer, offset + 69);
            ShortName = ByteReader.ReadUtf16String(buffer, offset + 70, _shortNameLength / 2);
            Reserved2 = LittleEndianConverter.ToUInt16(buffer, offset + 94);
            FileId = LittleEndianConverter.ToUInt64(buffer, offset + 96);
            FileName = ByteReader.ReadUtf16String(buffer, offset + 104, (int) _fileNameLength / 2);
        }

        public override FileInformationClass FileInformationClass =>
            FileInformationClass.FileIdBothDirectoryInformation;

        public override int Length => FixedLength + FileName.Length * 2;

        public override void WriteBytes(byte[] buffer, int offset)
        {
            base.WriteBytes(buffer, offset);
            _shortNameLength = (byte) (ShortName.Length * 2);
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
            ByteWriter.WriteByte(buffer, offset + 68, _shortNameLength);
            ByteWriter.WriteByte(buffer, offset + 69, Reserved1);
            ByteWriter.WriteUtf16String(buffer, offset + 70, ShortName);
            LittleEndianWriter.WriteUInt16(buffer, offset + 94, Reserved2);
            LittleEndianWriter.WriteUInt64(buffer, offset + 96, FileId);
            ByteWriter.WriteUtf16String(buffer, offset + 104, FileName);
        }
    }
}