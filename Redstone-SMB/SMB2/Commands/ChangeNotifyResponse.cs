/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Collections.Generic;
using RedstoneSmb.NTFileStore.Structures;
using RedstoneSmb.SMB2.Enums;
using ByteReader = RedstoneSmb.Utilities.ByteUtils.ByteReader;
using ByteWriter = RedstoneSmb.Utilities.ByteUtils.ByteWriter;
using LittleEndianConverter = RedstoneSmb.Utilities.Conversion.LittleEndianConverter;
using LittleEndianWriter = RedstoneSmb.Utilities.ByteUtils.LittleEndianWriter;

namespace RedstoneSmb.SMB2.Commands
{
    /// <summary>
    ///     SMB2 CHANGE_NOTIFY Response
    /// </summary>
    public class ChangeNotifyResponse : Smb2Command
    {
        public const int FixedSize = 8;
        public const int DeclaredSize = 9;
        public byte[] OutputBuffer = new byte[0];
        private uint _outputBufferLength;
        private ushort _outputBufferOffset;

        private readonly ushort _structureSize;

        public ChangeNotifyResponse() : base(Smb2CommandName.ChangeNotify)
        {
            Header.IsResponse = true;
            _structureSize = DeclaredSize;
        }

        public ChangeNotifyResponse(byte[] buffer, int offset) : base(buffer, offset)
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

        public List<FileNotifyInformation> GetFileNotifyInformation()
        {
            return FileNotifyInformation.ReadList(OutputBuffer, 0);
        }

        public void SetFileNotifyInformation(List<FileNotifyInformation> notifyInformationList)
        {
            OutputBuffer = FileNotifyInformation.GetBytes(notifyInformationList);
        }
    }
}