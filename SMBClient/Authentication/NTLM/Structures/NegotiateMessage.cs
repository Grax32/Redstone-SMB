/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.Authentication.NTLM.Helpers;
using SMBLibrary.Authentication.NTLM.Structures.Enums;
using SMBLibrary.Utilities.ByteUtils;
using SMBLibrary.Utilities.Conversion;
using ByteReader = SMBLibrary.Utilities.ByteUtils.ByteReader;
using ByteWriter = SMBLibrary.Utilities.ByteUtils.ByteWriter;
using LittleEndianConverter = SMBLibrary.Utilities.Conversion.LittleEndianConverter;
using LittleEndianWriter = SMBLibrary.Utilities.ByteUtils.LittleEndianWriter;

namespace SMBLibrary.Authentication.NTLM.Structures
{
    /// <summary>
    ///     [MS-NLMP] NEGOTIATE_MESSAGE (Type 1 Message)
    /// </summary>
    public class NegotiateMessage
    {
        public string DomainName;
        public MessageTypeName MessageType;
        public NegotiateFlags NegotiateFlags;
        public string Signature; // 8 bytes
        public NTLMVersion Version;
        public string Workstation;

        public NegotiateMessage()
        {
            Signature = AuthenticateMessage.ValidSignature;
            MessageType = MessageTypeName.Negotiate;
            DomainName = string.Empty;
            Workstation = string.Empty;
        }

        public NegotiateMessage(byte[] buffer)
        {
            Signature = ByteReader.ReadAnsiString(buffer, 0, 8);
            MessageType = (MessageTypeName) LittleEndianConverter.ToUInt32(buffer, 8);
            NegotiateFlags = (NegotiateFlags) LittleEndianConverter.ToUInt32(buffer, 12);
            DomainName = AuthenticationMessageUtils.ReadAnsiStringBufferPointer(buffer, 16);
            Workstation = AuthenticationMessageUtils.ReadAnsiStringBufferPointer(buffer, 24);
            if ((NegotiateFlags & NegotiateFlags.Version) > 0) Version = new NTLMVersion(buffer, 32);
        }

        public byte[] GetBytes()
        {
            if ((NegotiateFlags & NegotiateFlags.DomainNameSupplied) == 0) DomainName = string.Empty;

            if ((NegotiateFlags & NegotiateFlags.WorkstationNameSupplied) == 0) Workstation = string.Empty;

            var fixedLength = 32;
            if ((NegotiateFlags & NegotiateFlags.Version) > 0) fixedLength += 8;
            var payloadLength = DomainName.Length * 2 + Workstation.Length * 2;
            var buffer = new byte[fixedLength + payloadLength];
            ByteWriter.WriteAnsiString(buffer, 0, AuthenticateMessage.ValidSignature, 8);
            LittleEndianWriter.WriteUInt32(buffer, 8, (uint) MessageType);
            LittleEndianWriter.WriteUInt32(buffer, 12, (uint) NegotiateFlags);

            if ((NegotiateFlags & NegotiateFlags.Version) > 0) Version.WriteBytes(buffer, 32);

            var offset = fixedLength;
            AuthenticationMessageUtils.WriteBufferPointer(buffer, 16, (ushort) (DomainName.Length * 2), (uint) offset);
            ByteWriter.WriteUTF16String(buffer, ref offset, DomainName);
            AuthenticationMessageUtils.WriteBufferPointer(buffer, 24, (ushort) (Workstation.Length * 2), (uint) offset);
            ByteWriter.WriteUTF16String(buffer, ref offset, Workstation);

            return buffer;
        }
    }
}