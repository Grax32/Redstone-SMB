/* Copyright (C) 2018 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Collections.Generic;
using SMBLibrary.NTFileStore.Enums.AccessMask;
using SMBLibrary.NTFileStore.Enums.FileInformation;
using SMBLibrary.NTFileStore.Enums.NtCreateFile;
using SMBLibrary.NTFileStore.Enums.SecurityInformation;
using SMBLibrary.SMB2.Enums;
using SMBLibrary.SMB2.Enums.Create;
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
    ///     SMB2 CREATE Request
    /// </summary>
    public class CreateRequest : SMB2Command
    {
        public const int FixedLength = 56;
        public const int DeclaredSize = 57;
        public List<CreateContext> CreateContexts = new List<CreateContext>();
        private uint CreateContextsLength;
        private uint CreateContextsOffset; // 8-byte aligned
        public CreateDisposition CreateDisposition;
        public CreateOptions CreateOptions;
        public AccessMask DesiredAccess;
        public FileAttributes FileAttributes;
        public ImpersonationLevel ImpersonationLevel;
        public string Name;
        private ushort NameLength;
        private ushort NameOffset;
        public OplockLevel RequestedOplockLevel;
        public ulong Reserved;
        public byte SecurityFlags; // Reserved
        public ShareAccess ShareAccess;
        public ulong SmbCreateFlags;

        private readonly ushort StructureSize;

        public CreateRequest() : base(SMB2CommandName.Create)
        {
            StructureSize = DeclaredSize;
        }

        public CreateRequest(byte[] buffer, int offset) : base(buffer, offset)
        {
            StructureSize = LittleEndianConverter.ToUInt16(buffer, offset + SMB2Header.Length + 0);
            SecurityFlags = ByteReader.ReadByte(buffer, offset + SMB2Header.Length + 2);
            RequestedOplockLevel = (OplockLevel) ByteReader.ReadByte(buffer, offset + SMB2Header.Length + 3);
            ImpersonationLevel =
                (ImpersonationLevel) LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 4);
            SmbCreateFlags = LittleEndianConverter.ToUInt64(buffer, offset + SMB2Header.Length + 8);
            Reserved = LittleEndianConverter.ToUInt64(buffer, offset + SMB2Header.Length + 16);
            DesiredAccess = (AccessMask) LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 24);
            FileAttributes = (FileAttributes) LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 28);
            ShareAccess = (ShareAccess) LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 32);
            CreateDisposition =
                (CreateDisposition) LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 36);
            CreateOptions = (CreateOptions) LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 40);
            NameOffset = LittleEndianConverter.ToUInt16(buffer, offset + SMB2Header.Length + 44);
            NameLength = LittleEndianConverter.ToUInt16(buffer, offset + SMB2Header.Length + 46);
            CreateContextsOffset = LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 48);
            CreateContextsLength = LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 52);
            Name = ByteReader.ReadUTF16String(buffer, offset + NameOffset, NameLength / 2);
            if (CreateContextsLength > 0)
                CreateContexts = CreateContext.ReadCreateContextList(buffer, (int) CreateContextsOffset);
        }

        public override int CommandLength
        {
            get
            {
                int bufferLength;
                if (CreateContexts.Count == 0)
                {
                    bufferLength = Name.Length * 2;
                }
                else
                {
                    var paddedNameLength = (int) Math.Ceiling((double) (Name.Length * 2) / 8) * 8;
                    bufferLength = paddedNameLength + CreateContext.GetCreateContextListLength(CreateContexts);
                }

                // [MS-SMB2] The Buffer field MUST be at least one byte in length.
                return FixedLength + Math.Max(bufferLength, 1);
            }
        }

        public override void WriteCommandBytes(byte[] buffer, int offset)
        {
            // [MS-SMB2] The NameOffset field SHOULD be set to the offset of the Buffer field from the beginning of the SMB2 header.
            // Note: Windows 8.1 / 10 will return STATUS_INVALID_PARAMETER if NameOffset is set to 0.
            NameOffset = SMB2Header.Length + FixedLength;
            NameLength = (ushort) (Name.Length * 2);
            CreateContextsOffset = 0;
            CreateContextsLength = 0;
            var paddedNameLength = (int) Math.Ceiling((double) (Name.Length * 2) / 8) * 8;
            if (CreateContexts.Count > 0)
            {
                CreateContextsOffset = (uint) (SMB2Header.Length + FixedLength + paddedNameLength);
                CreateContextsLength = (uint) CreateContext.GetCreateContextListLength(CreateContexts);
            }

            LittleEndianWriter.WriteUInt16(buffer, offset + 0, StructureSize);
            ByteWriter.WriteByte(buffer, offset + 2, SecurityFlags);
            ByteWriter.WriteByte(buffer, offset + 3, (byte) RequestedOplockLevel);
            LittleEndianWriter.WriteUInt32(buffer, offset + 4, (uint) ImpersonationLevel);
            LittleEndianWriter.WriteUInt64(buffer, offset + 8, SmbCreateFlags);
            LittleEndianWriter.WriteUInt64(buffer, offset + 16, Reserved);
            LittleEndianWriter.WriteUInt32(buffer, offset + 24, (uint) DesiredAccess);
            LittleEndianWriter.WriteUInt32(buffer, offset + 28, (uint) FileAttributes);
            LittleEndianWriter.WriteUInt32(buffer, offset + 32, (uint) ShareAccess);
            LittleEndianWriter.WriteUInt32(buffer, offset + 36, (uint) CreateDisposition);
            LittleEndianWriter.WriteUInt32(buffer, offset + 40, (uint) CreateOptions);
            LittleEndianWriter.WriteUInt16(buffer, offset + 44, NameOffset);
            LittleEndianWriter.WriteUInt16(buffer, offset + 46, NameLength);
            LittleEndianWriter.WriteUInt32(buffer, offset + 48, CreateContextsOffset);
            LittleEndianWriter.WriteUInt32(buffer, offset + 52, CreateContextsLength);
            ByteWriter.WriteUTF16String(buffer, offset + 56, Name);
            CreateContext.WriteCreateContextList(buffer, offset + 56 + paddedNameLength, CreateContexts);
        }
    }
}