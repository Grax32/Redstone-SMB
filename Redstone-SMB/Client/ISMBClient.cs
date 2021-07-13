/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Collections.Generic;
using System.Net;
using RedstoneSmb.Client.Enums;
using RedstoneSmb.Enums;

namespace RedstoneSmb.Client
{
    public interface ISmbClient
    {
        uint MaxReadSize { get; }

        uint MaxWriteSize { get; }

        bool Connect(IPAddress serverAddress, SmbTransportType transport);

        void Disconnect();

        NtStatus Login(string domainName, string userName, string password);

        NtStatus Login(string domainName, string userName, string password, AuthenticationMethod authenticationMethod);

        NtStatus Logoff();

        List<string> ListShares(out NtStatus status);

        ISmbFileStore TreeConnect(string shareName, out NtStatus status);
    }
}