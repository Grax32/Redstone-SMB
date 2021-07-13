/* Copyright (C) 2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Net;
using System.Net.Sockets;
using RedstoneSmb.NetBios;
using RedstoneSmb.NetBios.NameServicePackets;
using RedstoneSmb.NetBios.NameServicePackets.Enums;

namespace RedstoneSmb.Client
{
    public class NameServiceClient
    {
        public static readonly int NetBiosNameServicePort = 137;

        private readonly IPAddress _mServerAddress;

        public NameServiceClient(IPAddress serverAddress)
        {
            _mServerAddress = serverAddress;
        }

        public string GetServerName()
        {
            var request = new NodeStatusRequest();
            request.Header.QdCount = 1;
            request.Question.Name = "*".PadRight(16, '\0');
            var response = SendNodeStatusRequest(request);
            foreach (var entry in response.Names)
            {
                var suffix = NetBiosUtils.GetSuffixFromMsNetBiosName(entry.Key);
                if (suffix == NetBiosSuffix.FileServiceService) return entry.Key;
            }

            return null;
        }

        private NodeStatusResponse SendNodeStatusRequest(NodeStatusRequest request)
        {
            var client = new UdpClient();
            var serverEndPoint = new IPEndPoint(_mServerAddress, NetBiosNameServicePort);
            client.Connect(serverEndPoint);

            var requestBytes = request.GetBytes();
            client.Send(requestBytes, requestBytes.Length);
            var responseBytes = client.Receive(ref serverEndPoint);
            return new NodeStatusResponse(responseBytes, 0);
        }
    }
}