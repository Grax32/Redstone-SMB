/* Copyright (C) 2017-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.IO;
using SMBLibrary.Utilities.ByteUtils;
using ByteReader = SMBLibrary.Utilities.ByteUtils.ByteReader;
using ByteWriter = SMBLibrary.Utilities.ByteUtils.ByteWriter;

namespace SMBLibrary.Authentication.GSSAPI.SPNEGO
{
    public enum NegState : byte
    {
        AcceptCompleted = 0x00,
        AcceptIncomplete = 0x01,
        Reject = 0x02,
        RequestMic = 0x03
    }

    /// <summary>
    ///     RFC 4178 - negTokenResp
    /// </summary>
    public class SimpleProtectedNegotiationTokenResponse : SimpleProtectedNegotiationToken
    {
        public const byte NegTokenRespTag = 0xA1;
        public const byte NegStateTag = 0xA0;
        public const byte SupportedMechanismTag = 0xA1;
        public const byte ResponseTokenTag = 0xA2;
        public const byte MechanismListMICTag = 0xA3;
        public byte[] MechanismListMIC; // Optional

        public NegState? NegState; // Optional
        public byte[] ResponseToken; // Optional
        public byte[] SupportedMechanism; // Optional

        public SimpleProtectedNegotiationTokenResponse()
        {
        }

        /// <param name="offset">The offset following the NegTokenResp tag</param>
        /// <exception cref="System.IO.InvalidDataException"></exception>
        public SimpleProtectedNegotiationTokenResponse(byte[] buffer, int offset)
        {
            var constuctionLength = DerEncodingHelper.ReadLength(buffer, ref offset);
            var tag = ByteReader.ReadByte(buffer, ref offset);
            if (tag != (byte) DerEncodingTag.Sequence) throw new InvalidDataException();
            var sequenceLength = DerEncodingHelper.ReadLength(buffer, ref offset);
            var sequenceEndOffset = offset + sequenceLength;
            while (offset < sequenceEndOffset)
            {
                tag = ByteReader.ReadByte(buffer, ref offset);
                if (tag == NegStateTag)
                    NegState = ReadNegState(buffer, ref offset);
                else if (tag == SupportedMechanismTag)
                    SupportedMechanism = ReadSupportedMechanism(buffer, ref offset);
                else if (tag == ResponseTokenTag)
                    ResponseToken = ReadResponseToken(buffer, ref offset);
                else if (tag == MechanismListMICTag)
                    MechanismListMIC = ReadMechanismListMIC(buffer, ref offset);
                else
                    throw new InvalidDataException("Invalid negTokenResp structure");
            }
        }

        public override byte[] GetBytes()
        {
            var sequenceLength = GetTokenFieldsLength();
            var sequenceLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(sequenceLength);
            var constructionLength = 1 + sequenceLengthFieldSize + sequenceLength;
            var constructionLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(constructionLength);
            var bufferSize = 1 + constructionLengthFieldSize + 1 + sequenceLengthFieldSize + sequenceLength;
            var buffer = new byte[bufferSize];
            var offset = 0;
            ByteWriter.WriteByte(buffer, ref offset, NegTokenRespTag);
            DerEncodingHelper.WriteLength(buffer, ref offset, constructionLength);
            ByteWriter.WriteByte(buffer, ref offset, (byte) DerEncodingTag.Sequence);
            DerEncodingHelper.WriteLength(buffer, ref offset, sequenceLength);
            if (NegState.HasValue) WriteNegState(buffer, ref offset, NegState.Value);
            if (SupportedMechanism != null) WriteSupportedMechanism(buffer, ref offset, SupportedMechanism);
            if (ResponseToken != null) WriteResponseToken(buffer, ref offset, ResponseToken);
            if (MechanismListMIC != null) WriteMechanismListMIC(buffer, ref offset, MechanismListMIC);
            return buffer;
        }

        private int GetTokenFieldsLength()
        {
            var result = 0;
            if (NegState.HasValue)
            {
                var negStateLength = 5;
                result += negStateLength;
            }

            if (SupportedMechanism != null)
            {
                var supportedMechanismBytesLengthFieldSize =
                    DerEncodingHelper.GetLengthFieldSize(SupportedMechanism.Length);
                var supportedMechanismConstructionLength =
                    1 + supportedMechanismBytesLengthFieldSize + SupportedMechanism.Length;
                var supportedMechanismConstructionLengthFieldSize =
                    DerEncodingHelper.GetLengthFieldSize(supportedMechanismConstructionLength);
                var supportedMechanismLength = 1 + supportedMechanismConstructionLengthFieldSize + 1 +
                                               supportedMechanismBytesLengthFieldSize + SupportedMechanism.Length;
                result += supportedMechanismLength;
            }

            if (ResponseToken != null)
            {
                var responseTokenBytesLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(ResponseToken.Length);
                var responseTokenConstructionLength = 1 + responseTokenBytesLengthFieldSize + ResponseToken.Length;
                var responseTokenConstructionLengthFieldSize =
                    DerEncodingHelper.GetLengthFieldSize(responseTokenConstructionLength);
                var responseTokenLength = 1 + responseTokenConstructionLengthFieldSize + 1 +
                                          responseTokenBytesLengthFieldSize + ResponseToken.Length;
                result += responseTokenLength;
            }

            if (MechanismListMIC != null)
            {
                var mechanismListMICBytesLengthFieldSize =
                    DerEncodingHelper.GetLengthFieldSize(MechanismListMIC.Length);
                var mechanismListMICConstructionLength =
                    1 + mechanismListMICBytesLengthFieldSize + MechanismListMIC.Length;
                var mechanismListMICConstructionLengthFieldSize =
                    DerEncodingHelper.GetLengthFieldSize(mechanismListMICConstructionLength);
                var responseTokenLength = 1 + mechanismListMICConstructionLengthFieldSize + 1 +
                                          mechanismListMICBytesLengthFieldSize + MechanismListMIC.Length;
                result += responseTokenLength;
            }

            return result;
        }

        private static NegState ReadNegState(byte[] buffer, ref int offset)
        {
            var length = DerEncodingHelper.ReadLength(buffer, ref offset);
            var tag = ByteReader.ReadByte(buffer, ref offset);
            if (tag != (byte) DerEncodingTag.Enum) throw new InvalidDataException();
            length = DerEncodingHelper.ReadLength(buffer, ref offset);
            return (NegState) ByteReader.ReadByte(buffer, ref offset);
        }

        private static byte[] ReadSupportedMechanism(byte[] buffer, ref int offset)
        {
            var constructionLength = DerEncodingHelper.ReadLength(buffer, ref offset);
            var tag = ByteReader.ReadByte(buffer, ref offset);
            if (tag != (byte) DerEncodingTag.ObjectIdentifier) throw new InvalidDataException();
            var length = DerEncodingHelper.ReadLength(buffer, ref offset);
            return ByteReader.ReadBytes(buffer, ref offset, length);
        }

        private static byte[] ReadResponseToken(byte[] buffer, ref int offset)
        {
            var constructionLength = DerEncodingHelper.ReadLength(buffer, ref offset);
            var tag = ByteReader.ReadByte(buffer, ref offset);
            if (tag != (byte) DerEncodingTag.ByteArray) throw new InvalidDataException();
            var length = DerEncodingHelper.ReadLength(buffer, ref offset);
            return ByteReader.ReadBytes(buffer, ref offset, length);
        }

        private static byte[] ReadMechanismListMIC(byte[] buffer, ref int offset)
        {
            var constructionLength = DerEncodingHelper.ReadLength(buffer, ref offset);
            var tag = ByteReader.ReadByte(buffer, ref offset);
            if (tag != (byte) DerEncodingTag.ByteArray) throw new InvalidDataException();
            var length = DerEncodingHelper.ReadLength(buffer, ref offset);
            return ByteReader.ReadBytes(buffer, ref offset, length);
        }

        private static void WriteNegState(byte[] buffer, ref int offset, NegState negState)
        {
            ByteWriter.WriteByte(buffer, ref offset, NegStateTag);
            DerEncodingHelper.WriteLength(buffer, ref offset, 3);
            ByteWriter.WriteByte(buffer, ref offset, (byte) DerEncodingTag.Enum);
            DerEncodingHelper.WriteLength(buffer, ref offset, 1);
            ByteWriter.WriteByte(buffer, ref offset, (byte) negState);
        }

        private static void WriteSupportedMechanism(byte[] buffer, ref int offset, byte[] supportedMechanism)
        {
            var supportedMechanismLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(supportedMechanism.Length);
            ByteWriter.WriteByte(buffer, ref offset, SupportedMechanismTag);
            DerEncodingHelper.WriteLength(buffer, ref offset,
                1 + supportedMechanismLengthFieldSize + supportedMechanism.Length);
            ByteWriter.WriteByte(buffer, ref offset, (byte) DerEncodingTag.ObjectIdentifier);
            DerEncodingHelper.WriteLength(buffer, ref offset, supportedMechanism.Length);
            ByteWriter.WriteBytes(buffer, ref offset, supportedMechanism);
        }

        private static void WriteResponseToken(byte[] buffer, ref int offset, byte[] responseToken)
        {
            var responseTokenLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(responseToken.Length);
            ByteWriter.WriteByte(buffer, ref offset, ResponseTokenTag);
            DerEncodingHelper.WriteLength(buffer, ref offset, 1 + responseTokenLengthFieldSize + responseToken.Length);
            ByteWriter.WriteByte(buffer, ref offset, (byte) DerEncodingTag.ByteArray);
            DerEncodingHelper.WriteLength(buffer, ref offset, responseToken.Length);
            ByteWriter.WriteBytes(buffer, ref offset, responseToken);
        }

        private static void WriteMechanismListMIC(byte[] buffer, ref int offset, byte[] mechanismListMIC)
        {
            var mechanismListMICLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(mechanismListMIC.Length);
            ByteWriter.WriteByte(buffer, ref offset, MechanismListMICTag);
            DerEncodingHelper.WriteLength(buffer, ref offset,
                1 + mechanismListMICLengthFieldSize + mechanismListMIC.Length);
            ByteWriter.WriteByte(buffer, ref offset, (byte) DerEncodingTag.ByteArray);
            DerEncodingHelper.WriteLength(buffer, ref offset, mechanismListMIC.Length);
            ByteWriter.WriteBytes(buffer, ref offset, mechanismListMIC);
        }
    }
}