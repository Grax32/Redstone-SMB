/* Copyright (C) 2017-2018 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using RedstoneSmb.Authentication.GSSAPI;
using RedstoneSmb.Authentication.GSSAPI.SPNEGO;
using RedstoneSmb.Authentication.NTLM.Helpers;
using RedstoneSmb.Authentication.NTLM.Structures;
using RedstoneSmb.Authentication.NTLM.Structures.Enums;
using RedstoneSmb.Client.Enums;
using ByteUtils = RedstoneSmb.Utilities.ByteUtils.ByteUtils;

namespace RedstoneSmb.Client.Helpers
{
    public class NtlmAuthenticationHelper
    {
        public static byte[] GetNegotiateMessage(byte[] securityBlob, string domainName,
            AuthenticationMethod authenticationMethod)
        {
            var useGssapi = false;
            if (securityBlob.Length > 0)
            {
                SimpleProtectedNegotiationTokenInit inputToken = null;
                try
                {
                    inputToken =
                        SimpleProtectedNegotiationToken.ReadToken(securityBlob, 0, true) as
                            SimpleProtectedNegotiationTokenInit;
                }
                catch
                {
                }

                if (inputToken == null || !ContainsMechanism(inputToken, GssProvider.NtlmsspIdentifier)) return null;
                useGssapi = true;
            }

            var negotiateMessage = new NegotiateMessage();
            negotiateMessage.NegotiateFlags = NegotiateFlags.UnicodeEncoding |
                                              NegotiateFlags.OemEncoding |
                                              NegotiateFlags.Sign |
                                              NegotiateFlags.NtlmSessionSecurity |
                                              NegotiateFlags.DomainNameSupplied |
                                              NegotiateFlags.WorkstationNameSupplied |
                                              NegotiateFlags.AlwaysSign |
                                              NegotiateFlags.Version |
                                              NegotiateFlags.Use128BitEncryption |
                                              NegotiateFlags.KeyExchange |
                                              NegotiateFlags.Use56BitEncryption;

            if (authenticationMethod == AuthenticationMethod.NtlMv1)
                negotiateMessage.NegotiateFlags |= NegotiateFlags.LanManagerSessionKey;
            else
                negotiateMessage.NegotiateFlags |= NegotiateFlags.ExtendedSessionSecurity;

            negotiateMessage.Version = NtlmVersion.Server2003;
            negotiateMessage.DomainName = domainName;
            negotiateMessage.Workstation = Environment.MachineName;
            if (useGssapi)
            {
                var outputToken = new SimpleProtectedNegotiationTokenInit();
                outputToken.MechanismTypeList = new List<byte[]>();
                outputToken.MechanismTypeList.Add(GssProvider.NtlmsspIdentifier);
                outputToken.MechanismToken = negotiateMessage.GetBytes();
                return outputToken.GetBytes(true);
            }

            return negotiateMessage.GetBytes();
        }

        public static byte[] GetAuthenticateMessage(byte[] securityBlob, string domainName, string userName,
            string password, AuthenticationMethod authenticationMethod, out byte[] sessionKey)
        {
            sessionKey = null;
            var useGssapi = false;
            SimpleProtectedNegotiationTokenResponse inputToken = null;
            try
            {
                inputToken =
                    SimpleProtectedNegotiationToken.ReadToken(securityBlob, 0, false) as
                        SimpleProtectedNegotiationTokenResponse;
            }
            catch
            {
            }

            ChallengeMessage challengeMessage;
            if (inputToken != null)
            {
                challengeMessage = GetChallengeMessage(inputToken.ResponseToken);
                useGssapi = true;
            }
            else
            {
                challengeMessage = GetChallengeMessage(securityBlob);
            }

            if (challengeMessage == null) return null;

            var time = DateTime.UtcNow;
            var clientChallenge = new byte[8];
            new Random().NextBytes(clientChallenge);

            var authenticateMessage = new AuthenticateMessage();
            // https://msdn.microsoft.com/en-us/library/cc236676.aspx
            authenticateMessage.NegotiateFlags = NegotiateFlags.Sign |
                                                 NegotiateFlags.NtlmSessionSecurity |
                                                 NegotiateFlags.AlwaysSign |
                                                 NegotiateFlags.Version |
                                                 NegotiateFlags.Use128BitEncryption |
                                                 NegotiateFlags.Use56BitEncryption;
            if ((challengeMessage.NegotiateFlags & NegotiateFlags.UnicodeEncoding) > 0)
                authenticateMessage.NegotiateFlags |= NegotiateFlags.UnicodeEncoding;
            else
                authenticateMessage.NegotiateFlags |= NegotiateFlags.OemEncoding;

            if ((challengeMessage.NegotiateFlags & NegotiateFlags.KeyExchange) > 0)
                authenticateMessage.NegotiateFlags |= NegotiateFlags.KeyExchange;

            if (authenticationMethod == AuthenticationMethod.NtlMv1)
                authenticateMessage.NegotiateFlags |= NegotiateFlags.LanManagerSessionKey;
            else
                authenticateMessage.NegotiateFlags |= NegotiateFlags.ExtendedSessionSecurity;

            authenticateMessage.UserName = userName;
            authenticateMessage.DomainName = domainName;
            authenticateMessage.WorkStation = Environment.MachineName;
            byte[] sessionBaseKey;
            byte[] keyExchangeKey;
            if (authenticationMethod == AuthenticationMethod.NtlMv1 ||
                authenticationMethod == AuthenticationMethod.NtlMv1ExtendedSessionSecurity)
            {
                if (authenticationMethod == AuthenticationMethod.NtlMv1)
                {
                    authenticateMessage.LmChallengeResponse =
                        NtlmCryptography.ComputeLMv1Response(challengeMessage.ServerChallenge, password);
                    authenticateMessage.NtChallengeResponse =
                        NtlmCryptography.ComputeNtlMv1Response(challengeMessage.ServerChallenge, password);
                }
                else // NTLMv1ExtendedSessionSecurity
                {
                    authenticateMessage.LmChallengeResponse = ByteUtils.Concatenate(clientChallenge, new byte[16]);
                    authenticateMessage.NtChallengeResponse =
                        NtlmCryptography.ComputeNtlMv1ExtendedSessionSecurityResponse(challengeMessage.ServerChallenge,
                            clientChallenge, password);
                }

                // https://msdn.microsoft.com/en-us/library/cc236699.aspx
                sessionBaseKey = new Md4().GetByteHashFromBytes(NtlmCryptography.NtowFv1(password));
                var lmowf = NtlmCryptography.LmowFv1(password);
                keyExchangeKey = NtlmCryptography.KxKey(sessionBaseKey, authenticateMessage.NegotiateFlags,
                    authenticateMessage.LmChallengeResponse, challengeMessage.ServerChallenge, lmowf);
            }
            else // NTLMv2
            {
                var clientChallengeStructure =
                    new NtlMv2ClientChallenge(time, clientChallenge, challengeMessage.TargetInfo);
                var clientChallengeStructurePadded = clientChallengeStructure.GetBytesPadded();
                var ntProofStr = NtlmCryptography.ComputeNtlMv2Proof(challengeMessage.ServerChallenge,
                    clientChallengeStructurePadded, password, userName, domainName);

                authenticateMessage.LmChallengeResponse = NtlmCryptography.ComputeLMv2Response(
                    challengeMessage.ServerChallenge, clientChallenge, password, userName, challengeMessage.TargetName);
                authenticateMessage.NtChallengeResponse =
                    ByteUtils.Concatenate(ntProofStr, clientChallengeStructurePadded);

                // https://msdn.microsoft.com/en-us/library/cc236700.aspx
                var responseKeyNt = NtlmCryptography.NtowFv2(password, userName, domainName);
                sessionBaseKey = new HMACMD5(responseKeyNt).ComputeHash(ntProofStr);
                keyExchangeKey = sessionBaseKey;
            }

            authenticateMessage.Version = NtlmVersion.Server2003;

            // https://msdn.microsoft.com/en-us/library/cc236676.aspx
            if ((challengeMessage.NegotiateFlags & NegotiateFlags.KeyExchange) > 0)
            {
                sessionKey = new byte[16];
                new Random().NextBytes(sessionKey);
                authenticateMessage.EncryptedRandomSessionKey = Rc4.Encrypt(keyExchangeKey, sessionKey);
            }
            else
            {
                sessionKey = keyExchangeKey;
            }

            if (useGssapi)
            {
                var outputToken = new SimpleProtectedNegotiationTokenResponse();
                outputToken.ResponseToken = authenticateMessage.GetBytes();
                return outputToken.GetBytes();
            }

            return authenticateMessage.GetBytes();
        }

        private static ChallengeMessage GetChallengeMessage(byte[] messageBytes)
        {
            if (AuthenticationMessageUtils.IsSignatureValid(messageBytes))
            {
                var messageType = AuthenticationMessageUtils.GetMessageType(messageBytes);
                if (messageType == MessageTypeName.Challenge)
                    try
                    {
                        return new ChallengeMessage(messageBytes);
                    }
                    catch
                    {
                        return null;
                    }
            }

            return null;
        }

        private static bool ContainsMechanism(SimpleProtectedNegotiationTokenInit token, byte[] mechanismIdentifier)
        {
            return token.MechanismTypeList.Any(t =>
                ByteUtils.AreByteArraysEqual(t, mechanismIdentifier)
            );
        }
    }
}