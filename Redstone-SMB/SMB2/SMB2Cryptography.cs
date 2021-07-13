/* Copyright (C) 2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Security.Cryptography;
using RedstoneSmb.Helpers;
using RedstoneSmb.SMB2.Enums;
using RedstoneSmb.SMB2.Enums.Negotiate;
using AesCcm = RedstoneSmb.Utilities.Cryptography.AesCcm;
using AesCmac = RedstoneSmb.Utilities.Cryptography.AesCmac;
using ByteReader = RedstoneSmb.Utilities.ByteUtils.ByteReader;
using ByteWriter = RedstoneSmb.Utilities.ByteUtils.ByteWriter;

namespace RedstoneSmb.SMB2
{
    internal class Smb2Cryptography
    {
        private const int AesCcmNonceLength = 11;

        public static byte[] CalculateSignature(byte[] signingKey, Smb2Dialect dialect, byte[] buffer, int offset,
            int paddedLength)
        {
            if (dialect == Smb2Dialect.Smb202 || dialect == Smb2Dialect.Smb210)
                return new HMACSHA256(signingKey).ComputeHash(buffer, offset, paddedLength);
            return AesCmac.CalculateAesCmac(signingKey, buffer, offset, paddedLength);
        }

        public static byte[] GenerateSigningKey(byte[] sessionKey, Smb2Dialect dialect,
            byte[] preauthIntegrityHashValue)
        {
            if (dialect == Smb2Dialect.Smb202 || dialect == Smb2Dialect.Smb210) return sessionKey;

            if (dialect == Smb2Dialect.Smb311 && preauthIntegrityHashValue == null)
                throw new ArgumentNullException(nameof(preauthIntegrityHashValue));

            var labelString = dialect == Smb2Dialect.Smb311 ? "SMBSigningKey" : "SMB2AESCMAC";
            var label = GetNullTerminatedAnsiString(labelString);
            var context = dialect == Smb2Dialect.Smb311
                ? preauthIntegrityHashValue
                : GetNullTerminatedAnsiString("SmbSign");

            var hmac = new HMACSHA256(sessionKey);
            return Sp8001008.DeriveKey(hmac, label, context, 128);
        }

        public static byte[] GenerateClientEncryptionKey(byte[] sessionKey, Smb2Dialect dialect,
            byte[] preauthIntegrityHashValue)
        {
            if (dialect == Smb2Dialect.Smb311 && preauthIntegrityHashValue == null)
                throw new ArgumentNullException(nameof(preauthIntegrityHashValue));

            var labelString = dialect == Smb2Dialect.Smb311 ? "SMBC2SCipherKey" : "SMB2AESCCM";
            var label = GetNullTerminatedAnsiString(labelString);
            var context = dialect == Smb2Dialect.Smb311
                ? preauthIntegrityHashValue
                : GetNullTerminatedAnsiString("ServerIn ");

            var hmac = new HMACSHA256(sessionKey);
            return Sp8001008.DeriveKey(hmac, label, context, 128);
        }

        public static byte[] GenerateClientDecryptionKey(byte[] sessionKey, Smb2Dialect dialect,
            byte[] preauthIntegrityHashValue)
        {
            if (dialect == Smb2Dialect.Smb311 && preauthIntegrityHashValue == null)
                throw new ArgumentNullException(nameof(preauthIntegrityHashValue));

            var labelString = dialect == Smb2Dialect.Smb311 ? "SMBS2CCipherKey" : "SMB2AESCCM";
            var label = GetNullTerminatedAnsiString(labelString);
            var context = dialect == Smb2Dialect.Smb311
                ? preauthIntegrityHashValue
                : GetNullTerminatedAnsiString("ServerOut");

            var hmac = new HMACSHA256(sessionKey);
            return Sp8001008.DeriveKey(hmac, label, context, 128);
        }

        /// <summary>
        ///     Encyrpt message and prefix with SMB2 TransformHeader
        /// </summary>
        public static byte[] TransformMessage(byte[] key, byte[] message, ulong sessionId)
        {
            var nonce = GenerateAesCcmNonce();
            byte[] signature;
            var encryptedMessage = EncryptMessage(key, nonce, message, sessionId, out signature);
            var transformHeader = CreateTransformHeader(nonce, message.Length, sessionId);
            transformHeader.Signature = signature;

            var buffer = new byte[Smb2TransformHeader.Length + message.Length];
            transformHeader.WriteBytes(buffer, 0);
            ByteWriter.WriteBytes(buffer, Smb2TransformHeader.Length, encryptedMessage);
            return buffer;
        }

        public static byte[] EncryptMessage(byte[] key, byte[] nonce, byte[] message, ulong sessionId,
            out byte[] signature)
        {
            var transformHeader = CreateTransformHeader(nonce, message.Length, sessionId);
            var associatedata = transformHeader.GetAssociatedData();
            return AesCcm.Encrypt(key, nonce, message, associatedata, Smb2TransformHeader.SignatureLength,
                out signature);
        }

        public static byte[] DecryptMessage(byte[] key, Smb2TransformHeader transformHeader, byte[] encryptedMessage)
        {
            var associatedData = transformHeader.GetAssociatedData();
            var aesCcmNonce = ByteReader.ReadBytes(transformHeader.Nonce, 0, AesCcmNonceLength);
            return AesCcm.DecryptAndAuthenticate(key, aesCcmNonce, encryptedMessage, associatedData,
                transformHeader.Signature);
        }

        private static Smb2TransformHeader CreateTransformHeader(byte[] nonce, int originalMessageLength,
            ulong sessionId)
        {
            var nonceWithPadding = new byte[Smb2TransformHeader.NonceLength];
            Array.Copy(nonce, nonceWithPadding, nonce.Length);

            var transformHeader = new Smb2TransformHeader();
            transformHeader.Nonce = nonceWithPadding;
            transformHeader.OriginalMessageSize = (uint) originalMessageLength;
            transformHeader.Flags = Smb2TransformHeaderFlags.Encrypted;
            transformHeader.SessionId = sessionId;

            return transformHeader;
        }

        private static byte[] GenerateAesCcmNonce()
        {
            var aesCcmNonce = new byte[AesCcmNonceLength];
            new Random().NextBytes(aesCcmNonce);
            return aesCcmNonce;
        }

        private static byte[] GetNullTerminatedAnsiString(string value)
        {
            var result = new byte[value.Length + 1];
            ByteWriter.WriteNullTerminatedAnsiString(result, 0, value);
            return result;
        }
    }
}