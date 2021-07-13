/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.NTFileStore.Enums.FileInformation;
using SMBLibrary.NTFileStore.Enums.FileSystemInformation;
using SMBLibrary.NTFileStore.Enums.SecurityInformation;
using SMBLibrary.NTFileStore.Structures.FileInformation;
using SMBLibrary.SMB2.Enums;
using SMBLibrary.SMB2.Structures;
using SMBLibrary.Utilities.ByteUtils;
using SMBLibrary.Utilities.Conversion;
using ByteReader = SMBLibrary.Utilities.ByteUtils.ByteReader;
using ByteWriter = SMBLibrary.Utilities.ByteUtils.ByteWriter;
using LittleEndianConverter = SMBLibrary.Utilities.Conversion.LittleEndianConverter;
using LittleEndianWriter = SMBLibrary.Utilities.ByteUtils.LittleEndianWriter;

namespace SMBLibrary.SMB2.Commands
{
    /// <summary>
    ///     SMB2 QUERY_INFO Request
    /// </summary>
    public class QueryInfoRequest : SMB2Command
    {
        public const int FixedSize = 40;
        public const int DeclaredSize = 41;
        public uint AdditionalInformation;
        public FileID FileId;
        private byte FileInfoClass;
        public uint Flags;
        public InfoType InfoType;
        public byte[] InputBuffer = new byte[0];
        private uint InputBufferLength;
        private ushort InputBufferOffset;
        public uint OutputBufferLength;
        public ushort Reserved;

        private readonly ushort StructureSize;

        public QueryInfoRequest() : base(SMB2CommandName.QueryInfo)
        {
            StructureSize = DeclaredSize;
        }

        public QueryInfoRequest(byte[] buffer, int offset) : base(buffer, offset)
        {
            StructureSize = LittleEndianConverter.ToUInt16(buffer, offset + SMB2Header.Length + 0);
            InfoType = (InfoType) ByteReader.ReadByte(buffer, offset + SMB2Header.Length + 2);
            FileInfoClass = ByteReader.ReadByte(buffer, offset + SMB2Header.Length + 3);
            OutputBufferLength = LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 4);
            InputBufferOffset = LittleEndianConverter.ToUInt16(buffer, offset + SMB2Header.Length + 8);
            Reserved = LittleEndianConverter.ToUInt16(buffer, offset + SMB2Header.Length + 10);
            InputBufferLength = LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 12);
            AdditionalInformation = LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 16);
            Flags = LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 20);
            FileId = new FileID(buffer, offset + SMB2Header.Length + 24);
            InputBuffer = ByteReader.ReadBytes(buffer, offset + InputBufferOffset, (int) InputBufferLength);
        }

        public FileInformationClass FileInformationClass
        {
            get => (FileInformationClass) FileInfoClass;
            set => FileInfoClass = (byte) value;
        }

        public FileSystemInformationClass FileSystemInformationClass
        {
            get => (FileSystemInformationClass) FileInfoClass;
            set => FileInfoClass = (byte) value;
        }

        public SecurityInformation SecurityInformation
        {
            get => (SecurityInformation) AdditionalInformation;
            set => AdditionalInformation = (uint) value;
        }

        public override int CommandLength => FixedSize + InputBuffer.Length;

        public override void WriteCommandBytes(byte[] buffer, int offset)
        {
            InputBufferOffset = 0;
            InputBufferLength = (uint) InputBuffer.Length;
            if (InputBuffer.Length > 0) InputBufferOffset = SMB2Header.Length + FixedSize;
            LittleEndianWriter.WriteUInt16(buffer, offset + 0, StructureSize);
            ByteWriter.WriteByte(buffer, offset + 2, (byte) InfoType);
            ByteWriter.WriteByte(buffer, offset + 3, FileInfoClass);
            LittleEndianWriter.WriteUInt32(buffer, offset + 4, OutputBufferLength);
            LittleEndianWriter.WriteUInt16(buffer, offset + 8, InputBufferOffset);
            LittleEndianWriter.WriteUInt16(buffer, offset + 10, Reserved);
            LittleEndianWriter.WriteUInt32(buffer, offset + 12, InputBufferLength);
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