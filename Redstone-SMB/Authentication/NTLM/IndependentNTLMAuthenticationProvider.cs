/* Copyright (C) 2014-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Security.Cryptography;
using RedstoneSmb.Authentication.GSSAPI.Enums;
using RedstoneSmb.Authentication.NTLM.Helpers;
using RedstoneSmb.Authentication.NTLM.Structures;
using RedstoneSmb.Authentication.NTLM.Structures.Enums;
using RedstoneSmb.Enums;
using ByteReader = RedstoneSmb.Utilities.ByteUtils.ByteReader;
using ByteUtils = RedstoneSmb.Utilities.ByteUtils.ByteUtils;

namespace RedstoneSmb.Authentication.NTLM
{
    /// <returns>null if the account does not exist</returns>
    public delegate string GetUserPassword(string userName);

    public class IndependentNtlmAuthenticationProvider : NtlmAuthenticationProviderBase
    {
        // Here is an account of the maximum number of times I have witnessed Windows 7 SP1 attempts to login
        // to a server with the same invalid credentials before displaying a login prompt:
        // Note: The number of login attempts is related to the number of slashes following the server name.
        // \\servername                                    -  8 login attempts
        // \\servername\sharename                          - 29 login attempts
        // \\servername\sharename\dir1                     - 52 login attempts
        // \\servername\sharename\dir1\dir2                - 71 login attempts
        // \\servername\sharename\dir1\dir2\dir3           - 63 login attempts
        // \\servername\sharename\dir1\dir2\dir3\dir4      - 81 login attempts
        // \\servername\sharename\dir1\dir2\dir3\dir4\dir5 - 57 login attempts
        private static readonly int DefaultMaxLoginAttemptsInWindow = 100;
        private static readonly TimeSpan DefaultLoginWindowDuration = new TimeSpan(0, 20, 0);
        private readonly GetUserPassword _mGetUserPassword;
        private readonly LoginCounter _mLoginCounter;

        /// <param name="getUserPassword">
        ///     The NTLM challenge response will be compared against the provided password.
        /// </param>
        public IndependentNtlmAuthenticationProvider(GetUserPassword getUserPassword) : this(getUserPassword,
            DefaultMaxLoginAttemptsInWindow, DefaultLoginWindowDuration)
        {
        }

        public IndependentNtlmAuthenticationProvider(GetUserPassword getUserPassword, int maxLoginAttemptsInWindow,
            TimeSpan loginWindowDuration)
        {
            _mGetUserPassword = getUserPassword;
            _mLoginCounter = new LoginCounter(maxLoginAttemptsInWindow, loginWindowDuration);
        }

        private bool EnableGuestLogin => _mGetUserPassword("Guest") == string.Empty;

        public override NtStatus GetChallengeMessage(out object context, byte[] negotiateMessageBytes,
            out byte[] challengeMessageBytes)
        {
            NegotiateMessage negotiateMessage;
            try
            {
                negotiateMessage = new NegotiateMessage(negotiateMessageBytes);
            }
            catch
            {
                context = null;
                challengeMessageBytes = null;
                return NtStatus.SecEInvalidToken;
            }

            var serverChallenge = GenerateServerChallenge();
            context = new AuthContext(serverChallenge);

            var challengeMessage = new ChallengeMessage();
            // https://msdn.microsoft.com/en-us/library/cc236691.aspx
            challengeMessage.NegotiateFlags = NegotiateFlags.TargetTypeServer |
                                              NegotiateFlags.TargetInfo |
                                              NegotiateFlags.TargetNameSupplied |
                                              NegotiateFlags.Version;
            // [MS-NLMP] NTLMSSP_NEGOTIATE_NTLM MUST be set in the [..] CHALLENGE_MESSAGE to the client.
            challengeMessage.NegotiateFlags |= NegotiateFlags.NtlmSessionSecurity;

            if ((negotiateMessage.NegotiateFlags & NegotiateFlags.UnicodeEncoding) > 0)
                challengeMessage.NegotiateFlags |= NegotiateFlags.UnicodeEncoding;
            else if ((negotiateMessage.NegotiateFlags & NegotiateFlags.OemEncoding) > 0)
                challengeMessage.NegotiateFlags |= NegotiateFlags.OemEncoding;

            if ((negotiateMessage.NegotiateFlags & NegotiateFlags.ExtendedSessionSecurity) > 0)
                challengeMessage.NegotiateFlags |= NegotiateFlags.ExtendedSessionSecurity;
            else if ((negotiateMessage.NegotiateFlags & NegotiateFlags.LanManagerSessionKey) > 0)
                challengeMessage.NegotiateFlags |= NegotiateFlags.LanManagerSessionKey;

            if ((negotiateMessage.NegotiateFlags & NegotiateFlags.Sign) > 0)
                // [MS-NLMP] If the client sends NTLMSSP_NEGOTIATE_SIGN to the server in the NEGOTIATE_MESSAGE,
                // the server MUST return NTLMSSP_NEGOTIATE_SIGN to the client in the CHALLENGE_MESSAGE.
                challengeMessage.NegotiateFlags |= NegotiateFlags.Sign;

            if ((negotiateMessage.NegotiateFlags & NegotiateFlags.Seal) > 0)
                // [MS-NLMP] If the client sends NTLMSSP_NEGOTIATE_SEAL to the server in the NEGOTIATE_MESSAGE,
                // the server MUST return NTLMSSP_NEGOTIATE_SEAL to the client in the CHALLENGE_MESSAGE.
                challengeMessage.NegotiateFlags |= NegotiateFlags.Seal;

            if ((negotiateMessage.NegotiateFlags & NegotiateFlags.Sign) > 0 ||
                (negotiateMessage.NegotiateFlags & NegotiateFlags.Seal) > 0)
            {
                if ((negotiateMessage.NegotiateFlags & NegotiateFlags.Use56BitEncryption) > 0)
                    // [MS-NLMP] If the client sends NTLMSSP_NEGOTIATE_SEAL or NTLMSSP_NEGOTIATE_SIGN with
                    // NTLMSSP_NEGOTIATE_56 to the server in the NEGOTIATE_MESSAGE, the server MUST return
                    // NTLMSSP_NEGOTIATE_56 to the client in the CHALLENGE_MESSAGE.
                    challengeMessage.NegotiateFlags |= NegotiateFlags.Use56BitEncryption;
                if ((negotiateMessage.NegotiateFlags & NegotiateFlags.Use128BitEncryption) > 0)
                    // [MS-NLMP] If the client sends NTLMSSP_NEGOTIATE_128 to the server in the NEGOTIATE_MESSAGE,
                    // the server MUST return NTLMSSP_NEGOTIATE_128 to the client in the CHALLENGE_MESSAGE only if
                    // the client sets NTLMSSP_NEGOTIATE_SEAL or NTLMSSP_NEGOTIATE_SIGN.
                    challengeMessage.NegotiateFlags |= NegotiateFlags.Use128BitEncryption;
            }

            if ((negotiateMessage.NegotiateFlags & NegotiateFlags.KeyExchange) > 0)
                challengeMessage.NegotiateFlags |= NegotiateFlags.KeyExchange;

            challengeMessage.TargetName = Environment.MachineName;
            challengeMessage.ServerChallenge = serverChallenge;
            challengeMessage.TargetInfo =
                AvPairUtils.GetAvPairSequence(Environment.MachineName, Environment.MachineName);
            challengeMessage.Version = NtlmVersion.Server2003;
            challengeMessageBytes = challengeMessage.GetBytes();
            return NtStatus.SecIContinueNeeded;
        }

        public override NtStatus Authenticate(object context, byte[] authenticateMessageBytes)
        {
            AuthenticateMessage message;
            try
            {
                message = new AuthenticateMessage(authenticateMessageBytes);
            }
            catch
            {
                return NtStatus.SecEInvalidToken;
            }

            var authContext = context as AuthContext;
            if (authContext == null)
                // There are two possible reasons for authContext to be null:
                // 1. We have a bug in our implementation, let's assume that's not the case,
                //    according to [MS-SMB2] 3.3.5.5.1 we aren't allowed to return SEC_E_INVALID_HANDLE anyway.
                // 2. The client sent AuthenticateMessage without sending NegotiateMessage first,
                //    in this case the correct response is SEC_E_INVALID_TOKEN.
                return NtStatus.SecEInvalidToken;

            authContext.DomainName = message.DomainName;
            authContext.UserName = message.UserName;
            authContext.WorkStation = message.WorkStation;
            if (message.Version != null) authContext.OsVersion = message.Version.ToString();

            if ((message.NegotiateFlags & NegotiateFlags.Anonymous) > 0)
            {
                if (EnableGuestLogin)
                {
                    authContext.IsGuest = true;
                    return NtStatus.StatusSuccess;
                }

                return NtStatus.StatusLogonFailure;
            }

            if (!_mLoginCounter.HasRemainingLoginAttempts(message.UserName.ToLower()))
                return NtStatus.StatusAccountLockedOut;

            var password = _mGetUserPassword(message.UserName);
            if (password == null)
            {
                if (EnableGuestLogin)
                {
                    authContext.IsGuest = true;
                    return NtStatus.StatusSuccess;
                }

                if (_mLoginCounter.HasRemainingLoginAttempts(message.UserName.ToLower(), true))
                    return NtStatus.StatusLogonFailure;
                return NtStatus.StatusAccountLockedOut;
            }

            bool success;
            var serverChallenge = authContext.ServerChallenge;
            byte[] sessionBaseKey;
            byte[] keyExchangeKey = null;
            if ((message.NegotiateFlags & NegotiateFlags.ExtendedSessionSecurity) > 0)
            {
                if (AuthenticationMessageUtils.IsNtlMv1ExtendedSessionSecurity(message.LmChallengeResponse))
                {
                    // NTLM v1 Extended Session Security:
                    success = AuthenticateV1Extended(password, serverChallenge, message.LmChallengeResponse,
                        message.NtChallengeResponse);
                    if (success)
                    {
                        // https://msdn.microsoft.com/en-us/library/cc236699.aspx
                        sessionBaseKey = new Md4().GetByteHashFromBytes(NtlmCryptography.NtowFv1(password));
                        var lmowf = NtlmCryptography.LmowFv1(password);
                        keyExchangeKey = NtlmCryptography.KxKey(sessionBaseKey, message.NegotiateFlags,
                            message.LmChallengeResponse, serverChallenge, lmowf);
                    }
                }
                else
                {
                    // NTLM v2:
                    success = AuthenticateV2(message.DomainName, message.UserName, password, serverChallenge,
                        message.LmChallengeResponse, message.NtChallengeResponse);
                    if (success)
                    {
                        // https://msdn.microsoft.com/en-us/library/cc236700.aspx
                        var responseKeyNt = NtlmCryptography.NtowFv2(password, message.UserName, message.DomainName);
                        var ntProofStr = ByteReader.ReadBytes(message.NtChallengeResponse, 0, 16);
                        sessionBaseKey = new HMACMD5(responseKeyNt).ComputeHash(ntProofStr);
                        keyExchangeKey = sessionBaseKey;
                    }
                }
            }
            else
            {
                success = AuthenticateV1(password, serverChallenge, message.LmChallengeResponse,
                    message.NtChallengeResponse);
                if (success)
                {
                    // https://msdn.microsoft.com/en-us/library/cc236699.aspx
                    sessionBaseKey = new Md4().GetByteHashFromBytes(NtlmCryptography.NtowFv1(password));
                    var lmowf = NtlmCryptography.LmowFv1(password);
                    keyExchangeKey = NtlmCryptography.KxKey(sessionBaseKey, message.NegotiateFlags,
                        message.LmChallengeResponse, serverChallenge, lmowf);
                }
            }

            if (success)
            {
                // https://msdn.microsoft.com/en-us/library/cc236676.aspx
                // https://blogs.msdn.microsoft.com/openspecification/2010/04/19/ntlm-keys-and-sundry-stuff/
                if ((message.NegotiateFlags & NegotiateFlags.KeyExchange) > 0)
                    authContext.SessionKey = Rc4.Decrypt(keyExchangeKey, message.EncryptedRandomSessionKey);
                else
                    authContext.SessionKey = keyExchangeKey;
                return NtStatus.StatusSuccess;
            }

            if (_mLoginCounter.HasRemainingLoginAttempts(message.UserName.ToLower(), true))
                return NtStatus.StatusLogonFailure;
            return NtStatus.StatusAccountLockedOut;
        }

        public override bool DeleteSecurityContext(ref object context)
        {
            context = null;
            return true;
        }

        public override object GetContextAttribute(object context, GssAttributeName attributeName)
        {
            if (!(context is AuthContext authContext)) return null;
            
            switch (attributeName)
            {
                case GssAttributeName.DomainName:
                    return authContext.DomainName;
                case GssAttributeName.IsGuest:
                    return authContext.IsGuest;
                case GssAttributeName.MachineName:
                    return authContext.WorkStation;
                case GssAttributeName.OsVersion:
                    return authContext.OsVersion;
                case GssAttributeName.SessionKey:
                    return authContext.SessionKey;
                case GssAttributeName.UserName:
                    return authContext.UserName;
            }

            return null;
        }

        /// <summary>
        ///     LM v1 / NTLM v1
        /// </summary>
        private static bool AuthenticateV1(string password, byte[] serverChallenge, byte[] lmResponse,
            byte[] ntResponse)
        {
            var expectedLmResponse = NtlmCryptography.ComputeLMv1Response(serverChallenge, password);
            if (ByteUtils.AreByteArraysEqual(expectedLmResponse, lmResponse)) return true;

            var expectedNtResponse = NtlmCryptography.ComputeNtlMv1Response(serverChallenge, password);
            return ByteUtils.AreByteArraysEqual(expectedNtResponse, ntResponse);
        }

        /// <summary>
        ///     LM v1 / NTLM v1 Extended Session Security
        /// </summary>
        private static bool AuthenticateV1Extended(string password, byte[] serverChallenge, byte[] lmResponse,
            byte[] ntResponse)
        {
            var clientChallenge = ByteReader.ReadBytes(lmResponse, 0, 8);
            var expectedNtlMv1Response =
                NtlmCryptography.ComputeNtlMv1ExtendedSessionSecurityResponse(serverChallenge, clientChallenge,
                    password);

            return ByteUtils.AreByteArraysEqual(expectedNtlMv1Response, ntResponse);
        }

        /// <summary>
        ///     LM v2 / NTLM v2
        /// </summary>
        private bool AuthenticateV2(string domainName, string accountName, string password, byte[] serverChallenge,
            byte[] lmResponse, byte[] ntResponse)
        {
            // Note: Linux CIFS VFS 3.10 will send LmChallengeResponse with length of 0 bytes
            if (lmResponse.Length == 24)
            {
                var lMv2ClientChallenge = ByteReader.ReadBytes(lmResponse, 16, 8);
                var expectedLMv2Response = NtlmCryptography.ComputeLMv2Response(serverChallenge, lMv2ClientChallenge,
                    password, accountName, domainName);
                if (ByteUtils.AreByteArraysEqual(expectedLMv2Response, lmResponse)) return true;
            }

            if (AuthenticationMessageUtils.IsNtlMv2NtResponse(ntResponse))
            {
                var clientNtProof = ByteReader.ReadBytes(ntResponse, 0, 16);
                var clientChallengeStructurePadded = ByteReader.ReadBytes(ntResponse, 16, ntResponse.Length - 16);
                var expectedNtProof = NtlmCryptography.ComputeNtlMv2Proof(serverChallenge,
                    clientChallengeStructurePadded, password, accountName, domainName);

                return ByteUtils.AreByteArraysEqual(clientNtProof, expectedNtProof);
            }

            return false;
        }

        /// <summary>
        ///     Generate 8-byte server challenge
        /// </summary>
        private static byte[] GenerateServerChallenge()
        {
            var serverChallenge = new byte[8];
            new Random().NextBytes(serverChallenge);
            return serverChallenge;
        }

        public class AuthContext
        {
            public string DomainName;
            public bool IsGuest;
            public string OsVersion;
            public byte[] ServerChallenge;
            public byte[] SessionKey;
            public string UserName;
            public string WorkStation;

            public AuthContext(byte[] serverChallenge)
            {
                ServerChallenge = serverChallenge;
            }
        }
    }
}