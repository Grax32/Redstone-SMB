/* Copyright (C) 2017-2021 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using SMBLibrary.Client.Enums;
using SMBLibrary.Client.Helpers;
using SMBLibrary.Enums;
using SMBLibrary.NetBios;
using SMBLibrary.NetBios.NameServicePackets.Enums;
using SMBLibrary.NetBios.SessionPackets;
using SMBLibrary.SMB2;
using SMBLibrary.SMB2.Commands;
using SMBLibrary.SMB2.Enums;
using SMBLibrary.SMB2.Enums.Negotiate;
using SMBLibrary.SMB2.Enums.SessionSetup;
using SMBLibrary.SMB2.Enums.TreeConnect;
using SMBLibrary.Utilities.ByteUtils;
using ByteReader = SMBLibrary.Utilities.ByteUtils.ByteReader;
using ShareType = SMBLibrary.Services.ServerService.EnumStructures.ShareType;

namespace SMBLibrary.Client
{
    public class SMB2Client : ISMBClient
    {
        public static readonly int NetBiosOverTCPPort = 139;
        public static readonly int DirectTCPPort = 445;

        public static readonly uint ClientMaxTransactSize = 1048576;
        public static readonly uint ClientMaxReadSize = 1048576;
        public static readonly uint ClientMaxWriteSize = 1048576;
        private static readonly ushort _desiredCredits = 16;

        private readonly object _incomingQueueLock = new object();
        private ushort _availableCredits = 1;
        private Socket _clientSocket;
        private byte[] _decryptionKey;
        private SMB2Dialect _dialect;
        private byte[] _encryptionKey;
        private bool _encryptSessionData;
        private readonly List<SMB2Command> _incomingQueue = new List<SMB2Command>();

        private readonly EventWaitHandle _incomingQueueEventHandle =
            new EventWaitHandle(false, EventResetMode.AutoReset);

        private bool _isConnected;
        private bool _isLoggedIn;

        private uint _messageID;
        private byte[] _securityBlob;
        private ulong _sessionID;
        private byte[] _sessionKey;

        private readonly EventWaitHandle _sessionResponseEventHandle =
            new EventWaitHandle(false, EventResetMode.AutoReset);

        private SessionPacket _sessionResponsePacket;
        private byte[] _signingKey;
        private bool _signingRequired;

        private SMBTransportType m_transport;

        public uint MaxTransactSize { get; private set; }

        public bool Connect(IPAddress serverAddress, SMBTransportType transport)
        {
            m_transport = transport;
            if (!_isConnected)
            {
                int port;
                if (transport == SMBTransportType.NetBiosOverTCP)
                    port = NetBiosOverTCPPort;
                else
                    port = DirectTCPPort;

                if (!ConnectSocket(serverAddress, port)) return false;

                if (transport == SMBTransportType.NetBiosOverTCP)
                {
                    var sessionRequest = new SessionRequestPacket();
                    sessionRequest.CalledName =
                        NetBiosUtils.GetMSNetBiosName("*SMBSERVER", NetBiosSuffix.FileServiceService);
                    sessionRequest.CallingName =
                        NetBiosUtils.GetMSNetBiosName(Environment.MachineName, NetBiosSuffix.WorkstationService);
                    TrySendPacket(_clientSocket, sessionRequest);

                    var sessionResponsePacket = WaitForSessionResponsePacket();
                    if (!(sessionResponsePacket is PositiveSessionResponsePacket))
                    {
                        _clientSocket.Disconnect(false);
                        if (!ConnectSocket(serverAddress, port)) return false;

                        var nameServiceClient = new NameServiceClient(serverAddress);
                        var serverName = nameServiceClient.GetServerName();
                        if (serverName == null) return false;

                        sessionRequest.CalledName = serverName;
                        TrySendPacket(_clientSocket, sessionRequest);

                        sessionResponsePacket = WaitForSessionResponsePacket();
                        if (!(sessionResponsePacket is PositiveSessionResponsePacket)) return false;
                    }
                }

                var supportsDialect = NegotiateDialect();
                if (!supportsDialect)
                    _clientSocket.Close();
                else
                    _isConnected = true;
            }

            return _isConnected;
        }

        public void Disconnect()
        {
            if (_isConnected)
            {
                _clientSocket.Disconnect(false);
                _isConnected = false;
            }
        }

        public NTStatus Login(string domainName, string userName, string password)
        {
            return Login(domainName, userName, password, AuthenticationMethod.NTLMv2);
        }

        public NTStatus Login(string domainName, string userName, string password,
            AuthenticationMethod authenticationMethod)
        {
            if (!_isConnected)
                throw new InvalidOperationException(
                    "A connection must be successfully established before attempting login");

            var negotiateMessage =
                NTLMAuthenticationHelper.GetNegotiateMessage(_securityBlob, domainName, authenticationMethod);
            if (negotiateMessage == null) return NTStatus.SEC_E_INVALID_TOKEN;

            var request = new SessionSetupRequest
            {
                SecurityMode = SecurityMode.SigningEnabled,
                SecurityBuffer = negotiateMessage
            };
            TrySendCommand(request);
            var response = WaitForCommand(request.MessageID);
            if (response != null)
            {
                if (response.Header.Status == NTStatus.STATUS_MORE_PROCESSING_REQUIRED &&
                    response is SessionSetupResponse)
                {
                    var authenticateMessage = NTLMAuthenticationHelper.GetAuthenticateMessage(
                        ((SessionSetupResponse) response).SecurityBuffer, domainName, userName, password,
                        authenticationMethod, out _sessionKey);
                    if (authenticateMessage == null) return NTStatus.SEC_E_INVALID_TOKEN;

                    _sessionID = response.Header.SessionID;
                    request = new SessionSetupRequest
                    {
                        SecurityMode = SecurityMode.SigningEnabled,
                        SecurityBuffer = authenticateMessage
                    };
                    TrySendCommand(request);
                    response = WaitForCommand(request.MessageID);
                    if (response != null)
                    {
                        _isLoggedIn = response.Header.Status == NTStatus.STATUS_SUCCESS;
                        if (_isLoggedIn)
                        {
                            _signingKey = SMB2Cryptography.GenerateSigningKey(_sessionKey, _dialect, null);
                            if (_dialect == SMB2Dialect.SMB300)
                            {
                                _encryptSessionData = (((SessionSetupResponse) response).SessionFlags &
                                                       SessionFlags.EncryptData) > 0;
                                _encryptionKey =
                                    SMB2Cryptography.GenerateClientEncryptionKey(_sessionKey, SMB2Dialect.SMB300, null);
                                _decryptionKey =
                                    SMB2Cryptography.GenerateClientDecryptionKey(_sessionKey, SMB2Dialect.SMB300, null);
                            }
                        }

                        return response.Header.Status;
                    }
                }
                else
                {
                    return response.Header.Status;
                }
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        public NTStatus Logoff()
        {
            if (!_isConnected)
                throw new InvalidOperationException(
                    "A login session must be successfully established before attempting logoff");

            var request = new LogoffRequest();
            TrySendCommand(request);

            var response = WaitForCommand(request.MessageID);
            if (response != null)
            {
                _isLoggedIn = response.Header.Status != NTStatus.STATUS_SUCCESS;
                return response.Header.Status;
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        public List<string> ListShares(out NTStatus status)
        {
            if (!_isConnected || !_isLoggedIn)
                throw new InvalidOperationException(
                    "A login session must be successfully established before retrieving share list");

            var namedPipeShare = TreeConnect("IPC$", out status);
            if (namedPipeShare == null) return null;

            var shares = ServerServiceHelper.ListShares(namedPipeShare, ShareType.DiskDrive, out status);
            namedPipeShare.Disconnect();
            return shares;
        }

        public ISMBFileStore TreeConnect(string shareName, out NTStatus status)
        {
            if (!_isConnected || !_isLoggedIn)
                throw new InvalidOperationException(
                    "A login session must be successfully established before connecting to a share");

            var serverIPAddress = ((IPEndPoint) _clientSocket.RemoteEndPoint).Address;
            var sharePath = $@"\\{serverIPAddress}\{shareName}";
            var request = new TreeConnectRequest();
            request.Path = sharePath;
            TrySendCommand(request);
            var response = WaitForCommand(request.MessageID);
            if (response != null)
            {
                status = response.Header.Status;
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is TreeConnectResponse)
                {
                    var encryptShareData = (((TreeConnectResponse) response).ShareFlags & ShareFlags.EncryptData) > 0;
                    return new SMB2FileStore(this, response.Header.TreeID, _encryptSessionData || encryptShareData);
                }
            }
            else
            {
                status = NTStatus.STATUS_INVALID_SMB;
            }

            return null;
        }

        public uint MaxReadSize { get; private set; }

        public uint MaxWriteSize { get; private set; }

        private bool ConnectSocket(IPAddress serverAddress, int port)
        {
            _clientSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

            try
            {
                _clientSocket.Connect(serverAddress, port);
            }
            catch (SocketException)
            {
                return false;
            }

            var state = new ConnectionState(_clientSocket);
            var buffer = state.ReceiveBuffer;
            _clientSocket.BeginReceive(buffer.Buffer, buffer.WriteOffset, buffer.AvailableLength, SocketFlags.None,
                OnClientSocketReceive, state);
            return true;
        }

        private bool NegotiateDialect()
        {
            var request = new NegotiateRequest();
            request.SecurityMode = SecurityMode.SigningEnabled;
            request.Capabilities = Capabilities.Encryption;
            request.ClientGuid = Guid.NewGuid();
            request.ClientStartTime = DateTime.Now;
            request.Dialects.Add(SMB2Dialect.SMB202);
            request.Dialects.Add(SMB2Dialect.SMB210);
            request.Dialects.Add(SMB2Dialect.SMB300);

            TrySendCommand(request);
            var response = WaitForCommand(request.MessageID) as NegotiateResponse;
            if (response != null && response.Header.Status == NTStatus.STATUS_SUCCESS)
            {
                _dialect = response.DialectRevision;
                _signingRequired = (response.SecurityMode & SecurityMode.SigningRequired) > 0;
                MaxTransactSize = Math.Min(response.MaxTransactSize, ClientMaxTransactSize);
                MaxReadSize = Math.Min(response.MaxReadSize, ClientMaxReadSize);
                MaxWriteSize = Math.Min(response.MaxWriteSize, ClientMaxWriteSize);
                _securityBlob = response.SecurityBuffer;
                return true;
            }

            return false;
        }

        private void OnClientSocketReceive(IAsyncResult ar)
        {
            var state = (ConnectionState) ar.AsyncState;
            var clientSocket = state.ClientSocket;

            if (!clientSocket.Connected) return;

            var numberOfBytesReceived = 0;
            try
            {
                numberOfBytesReceived = clientSocket.EndReceive(ar);
            }
            catch (
                ArgumentException) // The IAsyncResult object was not returned from the corresponding synchronous method on this class.
            {
                return;
            }
            catch (ObjectDisposedException)
            {
                Log("[ReceiveCallback] EndReceive ObjectDisposedException");
                return;
            }
            catch (SocketException ex)
            {
                Log("[ReceiveCallback] EndReceive SocketException: " + ex.Message);
                return;
            }

            if (numberOfBytesReceived == 0)
            {
                _isConnected = false;
            }
            else
            {
                var buffer = state.ReceiveBuffer;
                buffer.SetNumberOfBytesReceived(numberOfBytesReceived);
                ProcessConnectionBuffer(state);

                try
                {
                    clientSocket.BeginReceive(buffer.Buffer, buffer.WriteOffset, buffer.AvailableLength,
                        SocketFlags.None, OnClientSocketReceive, state);
                }
                catch (ObjectDisposedException)
                {
                    _isConnected = false;
                    Log("[ReceiveCallback] BeginReceive ObjectDisposedException");
                }
                catch (SocketException ex)
                {
                    _isConnected = false;
                    Log("[ReceiveCallback] BeginReceive SocketException: " + ex.Message);
                }
            }
        }

        private void ProcessConnectionBuffer(ConnectionState state)
        {
            var receiveBuffer = state.ReceiveBuffer;
            while (receiveBuffer.HasCompletePacket())
            {
                SessionPacket packet = null;
                try
                {
                    packet = receiveBuffer.DequeuePacket();
                }
                catch (Exception)
                {
                    state.ClientSocket.Close();
                    break;
                }

                if (packet != null) ProcessPacket(packet, state);
            }
        }

        private void ProcessPacket(SessionPacket packet, ConnectionState state)
        {
            if (packet is SessionMessagePacket)
            {
                byte[] messageBytes;
                if (_dialect == SMB2Dialect.SMB300 && SMB2TransformHeader.IsTransformHeader(packet.Trailer, 0))
                {
                    var transformHeader = new SMB2TransformHeader(packet.Trailer, 0);
                    var encryptedMessage = ByteReader.ReadBytes(packet.Trailer, SMB2TransformHeader.Length,
                        (int) transformHeader.OriginalMessageSize);
                    messageBytes = SMB2Cryptography.DecryptMessage(_decryptionKey, transformHeader, encryptedMessage);
                }
                else
                {
                    messageBytes = packet.Trailer;
                }

                SMB2Command command;
                try
                {
                    command = SMB2Command.ReadResponse(messageBytes, 0);
                }
                catch (Exception ex)
                {
                    Log("Invalid SMB2 response: " + ex.Message);
                    state.ClientSocket.Close();
                    _isConnected = false;
                    return;
                }

                _availableCredits += command.Header.Credits;

                if (m_transport == SMBTransportType.DirectTCPTransport &&
                    command is NegotiateResponse negotiateResponse)
                    if ((negotiateResponse.Capabilities & Capabilities.LargeMTU) > 0)
                    {
                        // [MS-SMB2] 3.2.5.1 Receiving Any Message - If the message size received exceeds Connection.MaxTransactSize, the client MUST disconnect the connection.
                        // Note: Windows clients do not enforce the MaxTransactSize value, we add 256 bytes.
                        var maxPacketSize = SessionPacket.HeaderLength +
                                            (int) Math.Min(negotiateResponse.MaxTransactSize, ClientMaxTransactSize) +
                                            256;
                        if (maxPacketSize > state.ReceiveBuffer.Buffer.Length)
                            state.ReceiveBuffer.IncreaseBufferSize(maxPacketSize);
                    }

                // [MS-SMB2] 3.2.5.1.2 - If the MessageId is 0xFFFFFFFFFFFFFFFF, this is not a reply to a previous request,
                // and the client MUST NOT attempt to locate the request, but instead process it as follows:
                // If the command field in the SMB2 header is SMB2 OPLOCK_BREAK, it MUST be processed as specified in 3.2.5.19.
                // Otherwise, the response MUST be discarded as invalid.
                if (command.Header.MessageID != 0xFFFFFFFFFFFFFFFF ||
                    command.Header.Command == SMB2CommandName.OplockBreak)
                    lock (_incomingQueueLock)
                    {
                        _incomingQueue.Add(command);
                        _incomingQueueEventHandle.Set();
                    }
            }
            else if ((packet is PositiveSessionResponsePacket || packet is NegativeSessionResponsePacket) &&
                     m_transport == SMBTransportType.NetBiosOverTCP)
            {
                _sessionResponsePacket = packet;
                _sessionResponseEventHandle.Set();
            }
            else if (packet is SessionKeepAlivePacket && m_transport == SMBTransportType.NetBiosOverTCP)
            {
                // [RFC 1001] NetBIOS session keep alives do not require a response from the NetBIOS peer
            }
            else
            {
                Log("Inappropriate NetBIOS session packet");
                state.ClientSocket.Close();
            }
        }

        internal SMB2Command WaitForCommand(ulong messageID)
        {
            const int TimeOut = 5000;
            var stopwatch = new Stopwatch();
            stopwatch.Start();
            while (stopwatch.ElapsedMilliseconds < TimeOut)
            {
                lock (_incomingQueueLock)
                {
                    for (var index = 0; index < _incomingQueue.Count; index++)
                    {
                        var command = _incomingQueue[index];

                        if (command.Header.MessageID == messageID)
                        {
                            _incomingQueue.RemoveAt(index);
                            if (command.Header.IsAsync && command.Header.Status == NTStatus.STATUS_PENDING)
                            {
                                index--;
                                continue;
                            }

                            return command;
                        }
                    }
                }

                _incomingQueueEventHandle.WaitOne(100);
            }

            return null;
        }

        internal SessionPacket WaitForSessionResponsePacket()
        {
            const int TimeOut = 5000;
            var stopwatch = new Stopwatch();
            stopwatch.Start();
            while (stopwatch.ElapsedMilliseconds < TimeOut)
            {
                if (_sessionResponsePacket != null)
                {
                    var result = _sessionResponsePacket;
                    _sessionResponsePacket = null;
                    return result;
                }

                _sessionResponseEventHandle.WaitOne(100);
            }

            return null;
        }

        private void Log(string message)
        {
            Debug.Print(message);
        }

        internal void TrySendCommand(SMB2Command request)
        {
            TrySendCommand(request, _encryptSessionData);
        }

        internal void TrySendCommand(SMB2Command request, bool encryptData)
        {
            if (_dialect == SMB2Dialect.SMB202 || m_transport == SMBTransportType.NetBiosOverTCP)
            {
                request.Header.CreditCharge = 0;
                request.Header.Credits = 1;
                _availableCredits -= 1;
            }
            else
            {
                if (request.Header.CreditCharge == 0) request.Header.CreditCharge = 1;

                if (_availableCredits < request.Header.CreditCharge) throw new Exception("Not enough credits");

                _availableCredits -= request.Header.CreditCharge;

                if (_availableCredits < _desiredCredits)
                    request.Header.Credits += (ushort) (_desiredCredits - _availableCredits);
            }

            request.Header.MessageID = _messageID;
            request.Header.SessionID = _sessionID;
            // [MS-SMB2] If the client encrypts the message [..] then the client MUST set the Signature field of the SMB2 header to zero
            if (_signingRequired && !encryptData)
            {
                request.Header.IsSigned = _sessionID != 0 &&
                                          (request.CommandName == SMB2CommandName.TreeConnect ||
                                           request.Header.TreeID != 0 ||
                                           _dialect == SMB2Dialect.SMB300 &&
                                           request.CommandName == SMB2CommandName.Logoff);
                if (request.Header.IsSigned)
                {
                    request.Header.Signature = new byte[16]; // Request could be reused
                    var buffer = request.GetBytes();
                    var signature =
                        SMB2Cryptography.CalculateSignature(_signingKey, _dialect, buffer, 0, buffer.Length);
                    // [MS-SMB2] The first 16 bytes of the hash MUST be copied into the 16-byte signature field of the SMB2 Header.
                    request.Header.Signature = ByteReader.ReadBytes(signature, 0, 16);
                }
            }

            TrySendCommand(_clientSocket, request, encryptData ? _encryptionKey : null);
            if (_dialect == SMB2Dialect.SMB202 || m_transport == SMBTransportType.NetBiosOverTCP)
                _messageID++;
            else
                _messageID += request.Header.CreditCharge;
        }

        public static void TrySendCommand(Socket socket, SMB2Command request, byte[] encryptionKey)
        {
            var packet = new SessionMessagePacket();
            if (encryptionKey != null)
            {
                var requestBytes = request.GetBytes();
                packet.Trailer =
                    SMB2Cryptography.TransformMessage(encryptionKey, requestBytes, request.Header.SessionID);
            }
            else
            {
                packet.Trailer = request.GetBytes();
            }

            TrySendPacket(socket, packet);
        }

        public static void TrySendPacket(Socket socket, SessionPacket packet)
        {
            try
            {
                var packetBytes = packet.GetBytes();
                socket.Send(packetBytes);
            }
            catch (SocketException)
            {
            }
            catch (ObjectDisposedException)
            {
            }
        }
    }
}