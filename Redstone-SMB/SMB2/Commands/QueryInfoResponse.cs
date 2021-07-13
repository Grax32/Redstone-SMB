/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using RedstoneSmb.NTFileStore.Enums.FileInformation;
using RedstoneSmb.NTFileStore.Enums.FileSystemInformation;
using RedstoneSmb.NTFileStore.Structures.FileInformation;
using RedstoneSmb.NTFileStore.Structures.FileSystemInformation;
using RedstoneSmb.NTFileStore.Structures.SecurityInformation;
using RedstoneSmb.SMB2.Enums;
using ByteReader = RedstoneSmb.Utilities.ByteUtils.ByteReader;
using ByteWriter = RedstoneSmb.Utilities.ByteUtils.ByteWriter;
using LittleEndianConverter = RedstoneSmb.Utilities.Conversion.LittleEndianConverter;
using LittleEndianWriter = RedstoneSmb.Utilities.ByteUtils.LittleEndianWriter;

namespace RedstoneSmb.SMB2.Commands
{
    /// <summary>
    ///     SMB2 QUERY_INFO Response
    /// </summary>
    public class QueryInfoResponse : Smb2Command
    {
        public const int FixedSize = 8;
        public const int DeclaredSize = 9;
        public byte[] OutputBuffer = new byte[0];
        private uint _outputBufferLength;
        private ushort _outputBufferOffset;

        private readonly ushort _structureSize;

        public QueryInfoResponse() : base(Smb2CommandName.QueryInfo)
        {
            Header.IsResponse = true;
            _structureSize = DeclaredSize;
        }

        public QueryInfoResponse(byte[] buffer, int offset) : base(buffer, offset)
        {
            _structureSize = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 0);
            _outputBufferOffset = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 2);
            _outputBufferLength = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 4);
            OutputBuffer = ByteReader.ReadBytes(buffer, offset + _outputBufferOffset, (int) _outputBufferLength);
        }

        public override int CommandLength => FixedSize + OutputBuffer.Length;

        public override void WriteCommandBytes(byte[] buffer, int offset)
        {
            _outputBufferOffset = 0;
            _outputBufferLength = (uint) OutputBuffer.Length;
            if (OutputBuffer.Length > 0) _outputBufferOffset = Smb2Header.Length + FixedSize;
            LittleEndianWriter.WriteUInt16(buffer, offset + 0, _structureSize);
            LittleEndianWriter.WriteUInt16(buffer, offset + 2, _outputBufferOffset);
            LittleEndianWriter.WriteUInt32(buffer, offset + 4, _outputBufferLength);
            ByteWriter.WriteBytes(buffer, offset + FixedSize, OutputBuffer);
        }

        public FileInformation GetFileInformation(FileInformationClass informationClass)
        {
            return FileInformation.GetFileInformation(OutputBuffer, 0, informationClass);
        }

        public FileSystemInformation GetFileSystemInformation(FileSystemInformationClass informationClass)
        {
            return FileSystemInformation.GetFileSystemInformation(OutputBuffer, 0, informationClass);
        }

        public SecurityDescriptor GetSecurityInformation()
        {
            return new SecurityDescriptor(OutputBuffer, 0);
        }

        public void SetFileInformation(FileInformation fileInformation)
        {
            OutputBuffer = fileInformation.GetBytes();
        }

        public void SetFileSystemInformation(FileSystemInformation fileSystemInformation)
        {
            OutputBuffer = fileSystemInformation.GetBytes();
        }

        public void SetSecurityInformation(SecurityDescriptor securityDescriptor)
        {
            OutputBuffer = securityDescriptor.GetBytes();
        }
    }
}