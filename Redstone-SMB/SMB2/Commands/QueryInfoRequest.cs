/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using RedstoneSmb.NTFileStore.Enums.FileInformation;
using RedstoneSmb.NTFileStore.Enums.FileSystemInformation;
using RedstoneSmb.NTFileStore.Enums.SecurityInformation;
using RedstoneSmb.NTFileStore.Structures.FileInformation;
using RedstoneSmb.SMB2.Enums;
using RedstoneSmb.SMB2.Structures;
using ByteReader = RedstoneSmb.Utilities.ByteUtils.ByteReader;
using ByteWriter = RedstoneSmb.Utilities.ByteUtils.ByteWriter;
using LittleEndianConverter = RedstoneSmb.Utilities.Conversion.LittleEndianConverter;
using LittleEndianWriter = RedstoneSmb.Utilities.ByteUtils.LittleEndianWriter;

namespace RedstoneSmb.SMB2.Commands
{
    /// <summary>
    ///     SMB2 QUERY_INFO Request
    /// </summary>
    public class QueryInfoRequest : Smb2Command
    {
        public const int FixedSize = 40;
        public const int DeclaredSize = 41;
        public uint AdditionalInformation;
        public FileId FileId;
        private byte _fileInfoClass;
        public uint Flags;
        public InfoType InfoType;
        public byte[] InputBuffer = new byte[0];
        private uint _inputBufferLength;
        private ushort _inputBufferOffset;
        public uint OutputBufferLength;
        public ushort Reserved;

        private readonly ushort _structureSize;

        public QueryInfoRequest() : base(Smb2CommandName.QueryInfo)
        {
            _structureSize = DeclaredSize;
        }

        public QueryInfoRequest(byte[] buffer, int offset) : base(buffer, offset)
        {
            _structureSize = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 0);
            InfoType = (InfoType) ByteReader.ReadByte(buffer, offset + Smb2Header.Length + 2);
            _fileInfoClass = ByteReader.ReadByte(buffer, offset + Smb2Header.Length + 3);
            OutputBufferLength = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 4);
            _inputBufferOffset = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 8);
            Reserved = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 10);
            _inputBufferLength = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 12);
            AdditionalInformation = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 16);
            Flags = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 20);
            FileId = new FileId(buffer, offset + Smb2Header.Length + 24);
            InputBuffer = ByteReader.ReadBytes(buffer, offset + _inputBufferOffset, (int) _inputBufferLength);
        }

        public FileInformationClass FileInformationClass
        {
            get => (FileInformationClass) _fileInfoClass;
            set => _fileInfoClass = (byte) value;
        }

        public FileSystemInformationClass FileSystemInformationClass
        {
            get => (FileSystemInformationClass) _fileInfoClass;
            set => _fileInfoClass = (byte) value;
        }

        public SecurityInformation SecurityInformation
        {
            get => (SecurityInformation) AdditionalInformation;
            set => AdditionalInformation = (uint) value;
        }

        public override int CommandLength => FixedSize + InputBuffer.Length;

        public override void WriteCommandBytes(byte[] buffer, int offset)
        {
            _inputBufferOffset = 0;
            _inputBufferLength = (uint) InputBuffer.Length;
            if (InputBuffer.Length > 0) _inputBufferOffset = Smb2Header.Length + FixedSize;
            LittleEndianWriter.WriteUInt16(buffer, offset + 0, _structureSize);
            ByteWriter.WriteByte(buffer, offset + 2, (byte) InfoType);
            ByteWriter.WriteByte(buffer, offset + 3, _fileInfoClass);
            LittleEndianWriter.WriteUInt32(buffer, offset + 4, OutputBufferLength);
            LittleEndianWriter.WriteUInt16(buffer, offset + 8, _inputBufferOffset);
            LittleEndianWriter.WriteUInt16(buffer, offset + 10, Reserved);
            LittleEndianWriter.WriteUInt32(buffer, offset + 12, _inputBufferLength);
            LittleEndianWriter.WriteUInt32(buffer, offset + 16, AdditionalInformation);
            LittleEndianWriter.WriteUInt32(buffer, offset + 20, Flags);
            FileId.WriteBytes(buffer, offset + 24);
            ByteWriter.WriteBytes(buffer, offset + FixedSize, InputBuffer);
        }

        public void SetFileInformation(FileInformation fileInformation)
        {
            InputBuffer = fileInformation.GetBytes();
        }
    }
}