/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using RedstoneSmb.SMB2.Enums;
using RedstoneSmb.SMB2.Enums.IOCtl;
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
    public class IoCtlRequest : Smb2Command
    {
        public const int FixedLength = 56;
        public const int DeclaredSize = 57;
        public uint CtlCode;
        public FileId FileId;
        public IoCtlRequestFlags Flags;
        public byte[] Input = new byte[0];
        private uint _inputCount;
        private uint _inputOffset;
        public uint MaxInputResponse;
        public uint MaxOutputResponse;
        public byte[] Output = new byte[0];
        private uint _outputCount;
        private uint _outputOffset;
        public ushort Reserved;
        public uint Reserved2;

        private readonly ushort _structureSize;

        public IoCtlRequest() : base(Smb2CommandName.IoCtl)
        {
            _structureSize = DeclaredSize;
        }

        public IoCtlRequest(byte[] buffer, int offset) : base(buffer, offset)
        {
            _structureSize = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 0);
            Reserved = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 2);
            CtlCode = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 4);
            FileId = new FileId(buffer, offset + Smb2Header.Length + 8);
            _inputOffset = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 24);
            _inputCount = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 28);
            MaxInputResponse = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 32);
            _outputOffset = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 36);
            _outputCount = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 40);
            MaxOutputResponse = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 44);
            Flags = (IoCtlRequestFlags) LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 48);
            Reserved2 = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 52);
            Input = ByteReader.ReadBytes(buffer, offset + (int) _inputOffset, (int) _inputCount);
            Output = ByteReader.ReadBytes(buffer, offset + (int) _outputOffset, (int) _outputCount);
        }

        public bool IsFsCtl
        {
            get => (Flags & IoCtlRequestFlags.IsFsCtl) > 0;
            set
            {
                if (value)
                    Flags |= IoCtlRequestFlags.IsFsCtl;
                else
                    Flags &= ~IoCtlRequestFlags.IsFsCtl;
            }
        }

        public override int CommandLength => FixedLength + Input.Length + Output.Length;

        public override void WriteCommandBytes(byte[] buffer, int offset)
        {
            _inputOffset = 0;
            _inputCount = (uint) Input.Length;
            _outputOffset = 0;
            _outputCount = (uint) Output.Length;
            if (Input.Length > 0) _inputOffset = Smb2Header.Length + FixedLength;
            if (Output.Length > 0) _outputOffset = Smb2Header.Length + FixedLength + (uint) Input.Length;
            LittleEndianWriter.WriteUInt16(buffer, offset + 0, _structureSize);
            LittleEndianWriter.WriteUInt16(buffer, offset + 2, Reserved);
            LittleEndianWriter.WriteUInt32(buffer, offset + 4, CtlCode);
            FileId.WriteBytes(buffer, offset + 8);
            LittleEndianWriter.WriteUInt32(buffer, offset + 24, _inputOffset);
            LittleEndianWriter.WriteUInt32(buffer, offset + 28, _inputCount);
            LittleEndianWriter.WriteUInt32(buffer, offset + 32, MaxInputResponse);
            LittleEndianWriter.WriteUInt32(buffer, offset + 36, _outputOffset);
            LittleEndianWriter.WriteUInt32(buffer, offset + 40, _outputCount);
            LittleEndianWriter.WriteUInt32(buffer, offset + 44, MaxOutputResponse);
            LittleEndianWriter.WriteUInt32(buffer, offset + 48, (uint) Flags);
            LittleEndianWriter.WriteUInt32(buffer, offset + 52, Reserved2);
            if (Input.Length > 0) ByteWriter.WriteBytes(buffer, offset + FixedLength, Input);
            if (Output.Length > 0) ByteWriter.WriteBytes(buffer, offset + FixedLength + Input.Length, Output);
        }
    }
}