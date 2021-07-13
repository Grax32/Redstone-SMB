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
using RedstoneSmb.NTFileStore.Structures.FileSystemInformation;
using RedstoneSmb.NTFileStore.Structures.SecurityInformation;
using RedstoneSmb.SMB2.Enums;
using RedstoneSmb.SMB2.Structures;
using ByteReader = RedstoneSmb.Utilities.ByteUtils.ByteReader;
using ByteWriter = RedstoneSmb.Utilities.ByteUtils.ByteWriter;
using LittleEndianConverter = RedstoneSmb.Utilities.Conversion.LittleEndianConverter;
using LittleEndianWriter = RedstoneSmb.Utilities.ByteUtils.LittleEndianWriter;

namespace RedstoneSmb.SMB2.Commands
{
    /// <summary>
    ///     SMB2 SET_INFO Request
    /// </summary>
    public class SetInfoRequest : Smb2Command
    {
        public const int FixedSize = 32;
        public const int DeclaredSize = 33;
        public uint AdditionalInformation;
        public byte[] Buffer = new byte[0];
        public uint BufferLength;
        private ushort _bufferOffset;
        public FileId FileId;
        private byte _fileInfoClass;
        public InfoType InfoType;
        public ushort Reserved;

        private readonly ushort _structureSize;

        public SetInfoRequest() : base(Smb2CommandName.SetInfo)
        {
            _structureSize = DeclaredSize;
        }

        public SetInfoRequest(byte[] buffer, int offset) : base(buffer, offset)
        {
            _structureSize = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 0);
            InfoType = (InfoType) ByteReader.ReadByte(buffer, offset + Smb2Header.Length + 2);
            _fileInfoClass = ByteReader.ReadByte(buffer, offset + Smb2Header.Length + 3);
            BufferLength = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 4);
            _bufferOffset = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 8);
            Reserved = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 10);
            AdditionalInformation = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 12);
            FileId = new FileId(buffer, offset + Smb2Header.Length + 16);
            Buffer = ByteReader.ReadBytes(buffer, offset + _bufferOffset, (int) BufferLength);
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

        public override int CommandLength => FixedSize + Buffer.Length;

        public override void WriteCommandBytes(byte[] buffer, int offset)
        {
            _bufferOffset = 0;
            BufferLength = (uint) Buffer.Length;
            if (Buffer.Length > 0) _bufferOffset = Smb2Header.Length + FixedSize;
            LittleEndianWriter.WriteUInt16(buffer, offset + 0, _structureSize);
            ByteWriter.WriteByte(buffer, offset + 2, (byte) InfoType);
            ByteWriter.WriteByte(buffer, offset + 3, _fileInfoClass);
            LittleEndianWriter.WriteUInt32(buffer, offset + 4, BufferLength);
            LittleEndianWriter.WriteUInt16(buffer, offset + 8, _bufferOffset);
            LittleEndianWriter.WriteUInt16(buffer, offset + 10, Reserved);
            LittleEndianWriter.WriteUInt32(buffer, offset + 12, AdditionalInformation);
            FileId.WriteBytes(buffer, offset + 16);
            ByteWriter.WriteBytes(buffer, offset + FixedSize, Buffer);
        }

        public void SetFileInformation(FileInformation fileInformation)
        {
            Buffer = fileInformation.GetBytes();
        }

        public void SetFileSystemInformation(FileSystemInformation fileSystemInformation)
        {
            Buffer = fileSystemInformation.GetBytes();
        }

        public void SetSecurityInformation(SecurityDescriptor securityDescriptor)
        {
            Buffer = securityDescriptor.GetBytes();
        }
    }
}