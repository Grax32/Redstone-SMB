/* Copyright (C) 2014-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using RedstoneSmb.Authentication.NTLM.Helpers;
using RedstoneSmb.Authentication.NTLM.Structures.Enums;
using ByteReader = RedstoneSmb.Utilities.ByteUtils.ByteReader;
using ByteWriter = RedstoneSmb.Utilities.ByteUtils.ByteWriter;
using LittleEndianConverter = RedstoneSmb.Utilities.Conversion.LittleEndianConverter;
using LittleEndianWriter = RedstoneSmb.Utilities.ByteUtils.LittleEndianWriter;

namespace RedstoneSmb.Authentication.NTLM.Structures
{
    /// <summary>
    ///     [MS-NLMP] AUTHENTICATE_MESSAGE (Type 3 Message)
    /// </summary>
    public class AuthenticateMessage
    {
        public const string ValidSignature = "NTLMSSP\0";
        public string DomainName;
        public byte[] EncryptedRandomSessionKey;

        public byte[]
            LmChallengeResponse; // 1 byte for anonymous authentication, 24 bytes for NTLM v1, NTLM v1 Extended Session Security and NTLM v2.

        public MessageTypeName MessageType;
        public byte[] Mic; // 16-byte MIC field is omitted for Windows NT / 2000 / XP / Server 2003
        public NegotiateFlags NegotiateFlags;

        public byte[]
            NtChallengeResponse; // 0 bytes for anonymous authentication, 24 bytes for NTLM v1 and NTLM v1 Extended Session Security, >= 48 bytes for NTLM v2.

        public string Signature; // 8 bytes
        public string UserName;
        public NtlmVersion Version;
        public string WorkStation;

        public AuthenticateMessage()
        {
            Signature = ValidSignature;
            MessageType = MessageTypeName.Authenticate;
            DomainName = string.Empty;
            UserName = string.Empty;
            WorkStation = string.Empty;
            EncryptedRandomSessionKey = new byte[0];
        }

        public AuthenticateMessage(byte[] buffer)
        {
            Signature = ByteReader.ReadAnsiString(buffer, 0, 8);
            MessageType = (MessageTypeName) LittleEndianConverter.ToUInt32(buffer, 8);
            LmChallengeResponse = AuthenticationMessageUtils.ReadBufferPointer(buffer, 12);
            NtChallengeResponse = AuthenticationMessageUtils.ReadBufferPointer(buffer, 20);
            DomainName = AuthenticationMessageUtils.ReadUnicodeStringBufferPointer(buffer, 28);
            UserName = AuthenticationMessageUtils.ReadUnicodeStringBufferPointer(buffer, 36);
            WorkStation = AuthenticationMessageUtils.ReadUnicodeStringBufferPointer(buffer, 44);
            EncryptedRandomSessionKey = AuthenticationMessageUtils.ReadBufferPointer(buffer, 52);
            NegotiateFlags = (NegotiateFlags) LittleEndianConverter.ToUInt32(buffer, 60);
            var offset = 64;
            if ((NegotiateFlags & NegotiateFlags.Version) > 0)
            {
                Version = new NtlmVersion(buffer, offset);
                offset += NtlmVersion.Length;
            }

            if (HasMicField()) Mic = ByteReader.ReadBytes(buffer, offset, 16);
        }

        public bool HasMicField()
        {
            if (!AuthenticationMessageUtils.IsNtlMv2NtResponse(NtChallengeResponse)) return false;

            NtlMv2ClientChallenge challenge;
            try
            {
                challenge = new NtlMv2ClientChallenge(NtChallengeResponse, 16);
            }
            catch
            {
                return false;
            }

            var index = challenge.AvPairs.IndexOfKey(AvPairKey.Flags);
            if (index >= 0)
            {
                var value = challenge.AvPairs[index].Value;
                if (value.Length == 4)
                {
                    var flags = LittleEndianConverter.ToInt32(value, 0);
                    return (flags & 0x02) > 0;
                }
            }

            return false;
        }

        public byte[] GetBytes()
        {
            if ((NegotiateFlags & NegotiateFlags.KeyExchange) == 0) EncryptedRandomSessionKey = new byte[0];

            var fixedLength = 64;
            if ((NegotiateFlags & NegotiateFlags.Version) > 0) fixedLength += NtlmVersion.Length;
            if (Mic != null) fixedLength += Mic.Length;
            var payloadLength = LmChallengeResponse.Length + NtChallengeResponse.Length + DomainName.Length * 2 +
                                UserName.Length * 2 + WorkStation.Length * 2 + EncryptedRandomSessionKey.Length;
            var buffer = new byte[fixedLength + payloadLength];
            ByteWriter.WriteAnsiString(buffer, 0, ValidSignature, 8);
            LittleEndianWriter.WriteUInt32(buffer, 8, (uint) MessageType);
            LittleEndianWriter.WriteUInt32(buffer, 60, (uint) NegotiateFlags);
            var offset = 64;
            if ((NegotiateFlags & NegotiateFlags.Version) > 0)
            {
                Version.WriteBytes(buffer, offset);
                offset += NtlmVersion.Length;
            }

            if (Mic != null)
            {
                ByteWriter.WriteBytes(buffer, offset, Mic);
                offset += Mic.Length;
            }

            AuthenticationMessageUtils.WriteBufferPointer(buffer, 28, (ushort) (DomainName.Length * 2), (uint) offset);
            ByteWriter.WriteUtf16String(buffer, ref offset, DomainName);
            AuthenticationMessageUtils.WriteBufferPointer(buffer, 36, (ushort) (UserName.Length * 2), (uint) offset);
            ByteWriter.WriteUtf16String(buffer, ref offset, UserName);
            AuthenticationMessageUtils.WriteBufferPointer(buffer, 44, (ushort) (WorkStation.Length * 2), (uint) offset);
            ByteWriter.WriteUtf16String(buffer, ref offset, WorkStation);
            AuthenticationMessageUtils.WriteBufferPointer(buffer, 12, (ushort) LmChallengeResponse.Length,
                (uint) offset);
            ByteWriter.WriteBytes(buffer, ref offset, LmChallengeResponse);
            AuthenticationMessageUtils.WriteBufferPointer(buffer, 20, (ushort) NtChallengeResponse.Length,
                (uint) offset);
            ByteWriter.WriteBytes(buffer, ref offset, NtChallengeResponse);
            AuthenticationMessageUtils.WriteBufferPointer(buffer, 52, (ushort) EncryptedRandomSessionKey.Length,
                (uint) offset);
            ByteWriter.WriteBytes(buffer, ref offset, EncryptedRandomSessionKey);

            return buffer;
        }
    }
}