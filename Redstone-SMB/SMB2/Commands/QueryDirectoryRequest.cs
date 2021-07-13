/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using RedstoneSmb.NTFileStore.Enums.FileInformation;
using RedstoneSmb.SMB2.Enums;
using RedstoneSmb.SMB2.Enums.QueryDirectory;
using RedstoneSmb.SMB2.Structures;
using ByteReader = RedstoneSmb.Utilities.ByteUtils.ByteReader;
using ByteWriter = RedstoneSmb.Utilities.ByteUtils.ByteWriter;
using LittleEndianConverter = RedstoneSmb.Utilities.Conversion.LittleEndianConverter;
using LittleEndianWriter = RedstoneSmb.Utilities.ByteUtils.LittleEndianWriter;

namespace RedstoneSmb.SMB2.Commands
{
    /// <summary>
    ///     SMB2 QUERY_DIRECTORY Request
    /// </summary>
    public class QueryDirectoryRequest : Smb2Command
    {
        public const int FixedLength = 32;
        public const int DeclaredSize = 33;
        public FileId FileId;
        public uint FileIndex;
        public FileInformationClass FileInformationClass;
        public string FileName = string.Empty;
        private ushort _fileNameLength;
        private ushort _fileNameOffset;
        public QueryDirectoryFlags Flags;
        public uint OutputBufferLength;

        private readonly ushort _structureSize;

        public QueryDirectoryRequest() : base(Smb2CommandName.QueryDirectory)
        {
            _structureSize = DeclaredSize;
        }

        public QueryDirectoryRequest(byte[] buffer, int offset) : base(buffer, offset)
        {
            _structureSize = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 0);
            FileInformationClass = (FileInformationClass) ByteReader.ReadByte(buffer, offset + Smb2Header.Length + 2);
            Flags = (QueryDirectoryFlags) ByteReader.ReadByte(buffer, offset + Smb2Header.Length + 3);
            FileIndex = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 4);
            FileId = new FileId(buffer, offset + Smb2Header.Length + 8);
            _fileNameOffset = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 24);
            _fileNameLength = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 26);
            OutputBufferLength = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 28);
            FileName = ByteReader.ReadUtf16String(buffer, offset + _fileNameOffset, _fileNameLength / 2);
        }

        public bool Restart
        {
            get => (Flags & QueryDirectoryFlags.Smb2RestartScans) > 0;
            set
            {
                if (value)
                    Flags |= QueryDirectoryFlags.Smb2RestartScans;
                else
                    Flags &= ~QueryDirectoryFlags.Smb2RestartScans;
            }
        }

        public bool ReturnSingleEntry
        {
            get => (Flags & QueryDirectoryFlags.Smb2ReturnSingleEntry) > 0;
            set
            {
                if (value)
                    Flags |= QueryDirectoryFlags.Smb2ReturnSingleEntry;
                else
                    Flags &= ~QueryDirectoryFlags.Smb2ReturnSingleEntry;
            }
        }

        public bool Reopen
        {
            get => (Flags & QueryDirectoryFlags.Smb2Reopen) > 0;
            set
            {
                if (value)
                    Flags |= QueryDirectoryFlags.Smb2Reopen;
                else
                    Flags &= ~QueryDirectoryFlags.Smb2Reopen;
            }
        }

        public override int CommandLength => FixedLength + FileName.Length * 2;

        public override void WriteCommandBytes(byte[] buffer, int offset)
        {
            _fileNameOffset = 0;
            _fileNameLength = (ushort) (FileName.Length * 2);
            if (FileName.Length > 0) _fileNameOffset = Smb2Header.Length + FixedLength;
            LittleEndianWriter.WriteUInt16(buffer, offset + 0, _structureSize);
            ByteWriter.WriteByte(buffer, offset + 2, (byte) FileInformationClass);
            ByteWriter.WriteByte(buffer, offset + 3, (byte) Flags);
            LittleEndianWriter.WriteUInt32(buffer, offset + 4, FileIndex);
            FileId.WriteBytes(buffer, offset + 8);
            LittleEndianWriter.WriteUInt16(buffer, offset + 24, _fileNameOffset);
            LittleEndianWriter.WriteUInt16(buffer, offset + 26, _fileNameLength);
            LittleEndianWriter.WriteUInt32(buffer, offset + 28, OutputBufferLength);
            ByteWriter.WriteUtf16String(buffer, offset + 32, FileName);
        }
    }
}