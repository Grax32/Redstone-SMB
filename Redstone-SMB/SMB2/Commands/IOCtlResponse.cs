/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using RedstoneSmb.SMB2.Enums;
using RedstoneSmb.SMB2.Structures;
using ByteReader = RedstoneSmb.Utilities.ByteUtils.ByteReader;
using ByteWriter = RedstoneSmb.Utilities.ByteUtils.ByteWriter;
using LittleEndianConverter = RedstoneSmb.Utilities.Conversion.LittleEndianConverter;
using LittleEndianWriter = RedstoneSmb.Utilities.ByteUtils.LittleEndianWriter;

namespace RedstoneSmb.SMB2.Commands
{
    /// <summary>
    ///     SMB2 IOCTL Request
    /// </summary>
    public class IoCtlResponse : Smb2Command
    {
        public const int FixedLength = 48;
        public const int DeclaredSize = 49;
        public uint CtlCode;
        public FileId FileId;
        public uint Flags;
        public byte[] Input = new byte[0];
        private uint _inputCount;
        private uint _inputOffset;
        public byte[] Output = new byte[0];
        private uint _outputCount;
        private uint _outputOffset;
        public ushort Reserved;
        public uint Reserved2;

        private readonly ushort _structureSize;

        public IoCtlResponse() : base(Smb2CommandName.IoCtl)
        {
            Header.IsResponse = true;
            _structureSize = DeclaredSize;
        }

        public IoCtlResponse(byte[] buffer, int offset) : base(buffer, offset)
        {
            _structureSize = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 0);
            Reserved = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 2);
            CtlCode = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 4);
            FileId = new FileId(buffer, offset + Smb2Header.Length + 8);
            _inputOffset = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 24);
            _inputCount = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 28);
            _outputOffset = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 32);
            _outputCount = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 36);
            Flags = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 40);
            Reserved2 = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 44);
            Input = ByteReader.ReadBytes(buffer, offset + (int) _inputOffset, (int) _inputCount);
            Output = ByteReader.ReadBytes(buffer, offset + (int) _outputOffset, (int) _outputCount);
        }

        public override int CommandLength
        {
            get
            {
                var paddedInputLength = (int) Math.Ceiling((double) Input.Length / 8) * 8;
                return FixedLength + paddedInputLength + Output.Length;
            }
        }

        public override void WriteCommandBytes(byte[] buffer, int offset)
        {
            _inputOffset = 0;
            _inputCount = (uint) Input.Length;
            _outputOffset = 0;
            _outputCount = (uint) Output.Length;
            if (Input.Length > 0) _inputOffset = Smb2Header.Length + FixedLength;
            // MS-SMB2: the output offset MUST be set to InputOffset + InputCount rounded up to a multiple of 8
            var paddedInputLength = (int) Math.Ceiling((double) Input.Length / 8) * 8;
            if (Output.Length > 0) _outputOffset = Smb2Header.Length + FixedLength + (uint) paddedInputLength;
            LittleEndianWriter.WriteUInt16(buffer, offset + 0, _structureSize);
            LittleEndianWriter.WriteUInt16(buffer, offset + 2, Reserved);
            LittleEndianWriter.WriteUInt32(buffer, offset + 4, CtlCode);
            FileId.WriteBytes(buffer, offset + 8);
            LittleEndianWriter.WriteUInt32(buffer, offset + 24, _inputOffset);
            LittleEndianWriter.WriteUInt32(buffer, offset + 28, _inputCount);
            LittleEndianWriter.WriteUInt32(buffer, offset + 32, _outputOffset);
            LittleEndianWriter.WriteUInt32(buffer, offset + 36, _outputCount);
            LittleEndianWriter.WriteUInt32(buffer, offset + 40, Flags);
            LittleEndianWriter.WriteUInt32(buffer, offset + 44, Reserved2);
            if (Input.Length > 0) ByteWriter.WriteBytes(buffer, offset + FixedLength, Input);
            if (Output.Length > 0) ByteWriter.WriteBytes(buffer, offset + FixedLength + paddedInputLength, Output);
        }
    }
}