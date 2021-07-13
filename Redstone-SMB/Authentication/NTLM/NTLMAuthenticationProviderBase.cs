/* Copyright (C) 2014-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using RedstoneSmb.Authentication.GSSAPI;
using RedstoneSmb.Authentication.GSSAPI.Enums;
using RedstoneSmb.Authentication.NTLM.Helpers;
using RedstoneSmb.Authentication.NTLM.Structures.Enums;
using RedstoneSmb.Enums;

namespace RedstoneSmb.Authentication.NTLM
{
    public abstract class NtlmAuthenticationProviderBase : IGssMechanism
    {
        public static readonly byte[] NtlmsspIdentifier = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a};

        public NtStatus AcceptSecurityContext(ref object context, byte[] inputToken, out byte[] outputToken)
        {
            outputToken = null;
            if (!AuthenticationMessageUtils.IsSignatureValid(inputToken)) return NtStatus.SecEInvalidToken;

            var messageType = AuthenticationMessageUtils.GetMessageType(inputToken);
            if (messageType == MessageTypeName.Negotiate)
            {
                var status = GetChallengeMessage(out context, inputToken, out outputToken);
                return status;
            }

            if (messageType == MessageTypeName.Authenticate)
                return Authenticate(context, inputToken);
            return NtStatus.SecEInvalidToken;
        }

        public abstract bool DeleteSecurityContext(ref object context);

        public abstract object GetContextAttribute(object context, GssAttributeName attributeName);

        public byte[] Identifier => NtlmsspIdentifier;

        public abstract NtStatus GetChallengeMessage(out object context, byte[] negotiateMessageBytes,
            out byte[] challengeMessageBytes);

        public abstract NtStatus Authenticate(object context, byte[] authenticateMessageBytes);
    }
}