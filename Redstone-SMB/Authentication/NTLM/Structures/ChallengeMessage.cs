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
using SMBLibrary.Utilities.Generics;
using ByteReader = SMBLibrary.Utilities.ByteUtils.ByteReader;
using ByteWriter = SMBLibrary.Utilities.ByteUtils.ByteWriter;
using LittleEndianConverter = SMBLibrary.Utilities.Conversion.LittleEndianConverter;
using LittleEndianWriter = SMBLibrary.Utilities.ByteUtils.LittleEndianWriter;

namespace SMBLibrary.Authentication.NTLM.Structures
{
    /// <summary>
    ///     [MS-NLMP] CHALLENGE_MESSAGE (Type 2 Message)
    /// </summary>
    public class ChallengeMessage
    {
        public MessageTypeName MessageType;
        public NegotiateFlags NegotiateFlags;
        public byte[] ServerChallenge; // 8 bytes

        public string Signature; // 8 bytes

        // Reserved - 8 bytes
        public Utilities.Generics.KeyValuePairList<AVPairKey, byte[]> TargetInfo = new Utilities.Generics.KeyValuePairList<AVPairKey, byte[]>();
        public string TargetName;
        public NTLMVersion Version;

        public ChallengeMessage()
        {
            Signature = AuthenticateMessage.ValidSignature;
            MessageType = MessageTypeName.Challenge;
        }

        public ChallengeMessage(byte[] buffer)
        {
            Signature = ByteReader.ReadAnsiString(buffer, 0, 8);
            MessageType = (MessageTypeName) LittleEndianConverter.ToUInt32(buffer, 8);
            TargetName = AuthenticationMessageUtils.ReadUnicodeStringBufferPointer(buffer, 12);
            NegotiateFlags = (NegotiateFlags) LittleEndianConverter.ToUInt32(buffer, 20);
            ServerChallenge = ByteReader.ReadBytes(buffer, 24, 8);
            // Reserved
            var targetInfoBytes = AuthenticationMessageUtils.ReadBufferPointer(buffer, 40);
            if (targetInfoBytes.Length > 0) TargetInfo = AVPairUtils.ReadAVPairSequence(targetInfoBytes, 0);
            if ((NegotiateFlags & NegotiateFlags.Version) > 0) Version = new NTLMVersion(buffer, 48);
        }

        public byte[] GetBytes()
        {
            if ((NegotiateFlags & NegotiateFlags.TargetNameSupplied) == 0) TargetName = string.Empty;

            var targetInfoBytes = AVPairUtils.GetAVPairSequenceBytes(TargetInfo);
            if ((NegotiateFlags & NegotiateFlags.TargetInfo) == 0) targetInfoBytes = new byte[0];

            var fixedLength = 48;
            if ((NegotiateFlags & NegotiateFlags.Version) > 0) fixedLength += 8;
            var payloadLength = TargetName.Length * 2 + targetInfoBytes.Length;
            var buffer = new byte[fixedLength + payloadLength];
            ByteWriter.WriteAnsiString(buffer, 0, AuthenticateMessage.ValidSignature, 8);
            LittleEndianWriter.WriteUInt32(buffer, 8, (uint) MessageType);
            LittleEndianWriter.WriteUInt32(buffer, 20, (uint) NegotiateFlags);
            ByteWriter.WriteBytes(buffer, 24, ServerChallenge);
            if ((NegotiateFlags & NegotiateFlags.Version) > 0) Version.WriteBytes(buffer, 48);

            var offset = fixedLength;
            AuthenticationMessageUtils.WriteBufferPointer(buffer, 12, (ushort) (TargetName.Length * 2), (uint) offset);
            ByteWriter.WriteUTF16String(buffer, ref offset, TargetName);
            AuthenticationMessageUtils.WriteBufferPointer(buffer, 40, (ushort) targetInfoBytes.Length, (uint) offset);
            ByteWriter.WriteBytes(buffer, ref offset, targetInfoBytes);

            return buffer;
        }
    }
}