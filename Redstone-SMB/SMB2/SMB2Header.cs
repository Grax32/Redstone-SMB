/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using RedstoneSmb.Enums;
using RedstoneSmb.SMB2.Enums;
using ByteReader = RedstoneSmb.Utilities.ByteUtils.ByteReader;
using ByteUtils = RedstoneSmb.Utilities.ByteUtils.ByteUtils;
using ByteWriter = RedstoneSmb.Utilities.ByteUtils.ByteWriter;
using LittleEndianConverter = RedstoneSmb.Utilities.Conversion.LittleEndianConverter;
using LittleEndianWriter = RedstoneSmb.Utilities.ByteUtils.LittleEndianWriter;

namespace RedstoneSmb.SMB2
{
    public class Smb2Header
    {
        public const int Length = 64;
        public const int SignatureOffset = 48;

        public static readonly byte[] ProtocolSignature = {0xFE, 0x53, 0x4D, 0x42};
        public ulong AsyncId; // Async
        public Smb2CommandName Command;
        public ushort CreditCharge;
        public ushort Credits; // CreditRequest or CreditResponse (The number of credits granted to the client)
        public Smb2PacketHeaderFlags Flags;
        public ulong MessageId;
        public uint NextCommand; // offset in bytes

        private readonly byte[] _protocolId; // 4 bytes, 0xFE followed by "SMB"
        public uint Reserved; // Sync
        public ulong SessionId;
        public byte[] Signature; // 16 bytes (present if SMB2_FLAGS_SIGNED is set)
        public NtStatus Status;
        private readonly ushort _structureSize;
        public uint TreeId; // Sync

        public Smb2Header(Smb2CommandName commandName)
        {
            _protocolId = ProtocolSignature;
            _structureSize = Length;
            Command = commandName;
            Signature = new byte[16];
        }

        public Smb2Header(byte[] buffer, int offset)
        {
            _protocolId = ByteReader.ReadBytes(buffer, offset + 0, 4);
            _structureSize = LittleEndianConverter.ToUInt16(buffer, offset + 4);
            CreditCharge = LittleEndianConverter.ToUInt16(buffer, offset + 6);
            Status = (NtStatus) LittleEndianConverter.ToUInt32(buffer, offset + 8);
            Command = (Smb2CommandName) LittleEndianConverter.ToUInt16(buffer, offset + 12);
            Credits = LittleEndianConverter.ToUInt16(buffer, offset + 14);
            Flags = (Smb2PacketHeaderFlags) LittleEndianConverter.ToUInt32(buffer, offset + 16);
            NextCommand = LittleEndianConverter.ToUInt32(buffer, offset + 20);
            MessageId = LittleEndianConverter.ToUInt64(buffer, offset + 24);
            if ((Flags & Smb2PacketHeaderFlags.AsyncCommand) > 0)
            {
                AsyncId = LittleEndianConverter.ToUInt64(buffer, offset + 32);
            }
            else
            {
                Reserved = LittleEndianConverter.ToUInt32(buffer, offset + 32);
                TreeId = LittleEndianConverter.ToUInt32(buffer, offset + 36);
            }

            SessionId = LittleEndianConverter.ToUInt64(buffer, offset + 40);
            if ((Flags & Smb2PacketHeaderFlags.Signed) > 0) Signature = ByteReader.ReadBytes(buffer, offset + 48, 16);
        }

        public bool IsResponse
        {
            get => (Flags & Smb2PacketHeaderFlags.ServerToRedir) > 0;
            set
            {
                if (value)
                    Flags |= Smb2PacketHeaderFlags.ServerToRedir;
                else
                    Flags &= ~Smb2PacketHeaderFlags.ServerToRedir;
            }
        }

        public bool IsAsync
        {
            get => (Flags & Smb2PacketHeaderFlags.AsyncCommand) > 0;
            set
            {
                if (value)
                    Flags |= Smb2PacketHeaderFlags.AsyncCommand;
                else
                    Flags &= ~Smb2PacketHeaderFlags.AsyncCommand;
            }
        }

        public bool IsRelatedOperations
        {
            get => (Flags & Smb2PacketHeaderFlags.RelatedOperations) > 0;
            set
            {
                if (value)
                    Flags |= Smb2PacketHeaderFlags.RelatedOperations;
                else
                    Flags &= ~Smb2PacketHeaderFlags.RelatedOperations;
            }
        }

        public bool IsSigned
        {
            get => (Flags & Smb2PacketHeaderFlags.Signed) > 0;
            set
            {
                if (value)
                    Flags |= Smb2PacketHeaderFlags.Signed;
                else
                    Flags &= ~Smb2PacketHeaderFlags.Signed;
            }
        }

        public void WriteBytes(byte[] buffer, int offset)
        {
            ByteWriter.WriteBytes(buffer, offset + 0, _protocolId);
            LittleEndianWriter.WriteUInt16(buffer, offset + 4, _structureSize);
            LittleEndianWriter.WriteUInt16(buffer, offset + 6, CreditCharge);
            LittleEndianWriter.WriteUInt32(buffer, offset + 8, (uint) Status);
            LittleEndianWriter.WriteUInt16(buffer, offset + 12, (ushort) Command);
            LittleEndianWriter.WriteUInt16(buffer, offset + 14, Credits);
            LittleEndianWriter.WriteUInt32(buffer, offset + 16, (uint) Flags);
            LittleEndianWriter.WriteUInt32(buffer, offset + 20, NextCommand);
            LittleEndianWriter.WriteUInt64(buffer, offset + 24, MessageId);
            if ((Flags & Smb2PacketHeaderFlags.AsyncCommand) > 0)
            {
                LittleEndianWriter.WriteUInt64(buffer, offset + 32, AsyncId);
            }
            else
            {
                LittleEndianWriter.WriteUInt32(buffer, offset + 32, Reserved);
                LittleEndianWriter.WriteUInt32(buffer, offset + 36, TreeId);
            }

            LittleEndianWriter.WriteUInt64(buffer, offset + 40, SessionId);
            if ((Flags & Smb2PacketHeaderFlags.Signed) > 0) ByteWriter.WriteBytes(buffer, offset + 48, Signature);
        }

        public static bool IsValidSmb2Header(byte[] buffer)
        {
            if (buffer.Length >= 4)
            {
                var protocol = ByteReader.ReadBytes(buffer, 0, 4);
                return ByteUtils.AreByteArraysEqual(protocol, ProtocolSignature);
            }

            return false;
        }
    }
}