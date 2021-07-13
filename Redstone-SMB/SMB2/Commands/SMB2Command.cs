/* Copyright (C) 2017-2021 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Collections.Generic;
using System.IO;
using RedstoneSmb.Enums;
using RedstoneSmb.SMB2.Enums;
using RedstoneSmb.SMB2.Enums.Negotiate;
using ByteWriter = RedstoneSmb.Utilities.ByteUtils.ByteWriter;
using LittleEndianConverter = RedstoneSmb.Utilities.Conversion.LittleEndianConverter;

namespace RedstoneSmb.SMB2.Commands
{
    public abstract class Smb2Command
    {
        public Smb2Header Header;

        protected Smb2Command(Smb2CommandName commandName)
        {
            Header = new Smb2Header(commandName);
        }

        protected Smb2Command(byte[] buffer, int offset)
        {
            Header = new Smb2Header(buffer, offset);
        }

        public Smb2CommandName CommandName => Header.Command;

        public ulong MessageId => Header.MessageId;

        public int Length => Smb2Header.Length + CommandLength;

        public abstract int CommandLength { get; }

        public void WriteBytes(byte[] buffer, int offset)
        {
            Header.WriteBytes(buffer, offset);
            WriteCommandBytes(buffer, offset + Smb2Header.Length);
        }

        public abstract void WriteCommandBytes(byte[] buffer, int offset);

        public byte[] GetBytes()
        {
            var buffer = new byte[Length];
            WriteBytes(buffer, 0);
            return buffer;
        }

        public static Smb2Command ReadRequest(byte[] buffer, int offset)
        {
            var commandName = (Smb2CommandName) LittleEndianConverter.ToUInt16(buffer, offset + 12);
            switch (commandName)
            {
                case Smb2CommandName.Negotiate:
                    return new NegotiateRequest(buffer, offset);
                case Smb2CommandName.SessionSetup:
                    return new SessionSetupRequest(buffer, offset);
                case Smb2CommandName.Logoff:
                    return new LogoffRequest(buffer, offset);
                case Smb2CommandName.TreeConnect:
                    return new TreeConnectRequest(buffer, offset);
                case Smb2CommandName.TreeDisconnect:
                    return new TreeDisconnectRequest(buffer, offset);
                case Smb2CommandName.Create:
                    return new CreateRequest(buffer, offset);
                case Smb2CommandName.Close:
                    return new CloseRequest(buffer, offset);
                case Smb2CommandName.Flush:
                    return new FlushRequest(buffer, offset);
                case Smb2CommandName.Read:
                    return new ReadRequest(buffer, offset);
                case Smb2CommandName.Write:
                    return new WriteRequest(buffer, offset);
                case Smb2CommandName.Lock:
                    return new LockRequest(buffer, offset);
                case Smb2CommandName.IoCtl:
                    return new IoCtlRequest(buffer, offset);
                case Smb2CommandName.Cancel:
                    return new CancelRequest(buffer, offset);
                case Smb2CommandName.Echo:
                    return new EchoRequest(buffer, offset);
                case Smb2CommandName.QueryDirectory:
                    return new QueryDirectoryRequest(buffer, offset);
                case Smb2CommandName.ChangeNotify:
                    return new ChangeNotifyRequest(buffer, offset);
                case Smb2CommandName.QueryInfo:
                    return new QueryInfoRequest(buffer, offset);
                case Smb2CommandName.SetInfo:
                    return new SetInfoRequest(buffer, offset);
                default:
                    throw new InvalidDataException("Invalid SMB2 command 0x" + ((ushort) commandName).ToString("X4"));
            }
        }

        public static List<Smb2Command> ReadRequestChain(byte[] buffer, int offset)
        {
            var result = new List<Smb2Command>();
            Smb2Command command;
            do
            {
                command = ReadRequest(buffer, offset);
                result.Add(command);
                offset += (int) command.Header.NextCommand;
            } while (command.Header.NextCommand != 0);

            return result;
        }

        public static byte[] GetCommandChainBytes(List<Smb2Command> commands)
        {
            return GetCommandChainBytes(commands, null, Smb2Dialect.Smb2Xx);
        }

        /// <param name="dialect">
        ///     Used for signature calculation when applicable.
        /// </param>
        public static byte[] GetCommandChainBytes(List<Smb2Command> commands, byte[] signingKey, Smb2Dialect dialect)
        {
            var totalLength = 0;
            for (var index = 0; index < commands.Count; index++)
            {
                // Any subsequent SMB2 header MUST be 8-byte aligned
                var length = commands[index].Length;
                if (index < commands.Count - 1)
                {
                    var paddedLength = (int) Math.Ceiling((double) length / 8) * 8;
                    totalLength += paddedLength;
                }
                else
                {
                    totalLength += length;
                }
            }

            var buffer = new byte[totalLength];
            var offset = 0;
            for (var index = 0; index < commands.Count; index++)
            {
                var command = commands[index];
                var commandLength = command.Length;
                int paddedLength;
                if (index < commands.Count - 1)
                {
                    paddedLength = (int) Math.Ceiling((double) commandLength / 8) * 8;
                    command.Header.NextCommand = (uint) paddedLength;
                }
                else
                {
                    paddedLength = commandLength;
                }

                command.WriteBytes(buffer, offset);
                if (command.Header.IsSigned && signingKey != null)
                {
                    // [MS-SMB2] Any padding at the end of the message MUST be used in the hash computation.
                    var signature =
                        Smb2Cryptography.CalculateSignature(signingKey, dialect, buffer, offset, paddedLength);
                    // [MS-SMB2] The first 16 bytes of the hash MUST be copied into the 16-byte signature field of the SMB2 Header.
                    ByteWriter.WriteBytes(buffer, offset + Smb2Header.SignatureOffset, signature, 16);
                }

                offset += paddedLength;
            }

            return buffer;
        }

        public static Smb2Command ReadResponse(byte[] buffer, int offset)
        {
            var commandName = (Smb2CommandName) LittleEndianConverter.ToUInt16(buffer, offset + 12);
            var structureSize = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 0);
            switch (commandName)
            {
                case Smb2CommandName.Negotiate:
                {
                    if (structureSize == NegotiateResponse.DeclaredSize)
                        return new NegotiateResponse(buffer, offset);
                    if (structureSize == ErrorResponse.DeclaredSize)
                        return new ErrorResponse(buffer, offset);
                    throw new InvalidDataException();
                }
                case Smb2CommandName.SessionSetup:
                {
                    // SESSION_SETUP Response and ERROR Response have the same declared StructureSize of 9.
                    if (structureSize == SessionSetupResponse.DeclaredSize)
                    {
                        var status = (NtStatus) LittleEndianConverter.ToUInt32(buffer, offset + 8);
                        if (status == NtStatus.StatusSuccess || status == NtStatus.StatusMoreProcessingRequired)
                            return new SessionSetupResponse(buffer, offset);
                        return new ErrorResponse(buffer, offset);
                    }

                    throw new InvalidDataException();
                }
                case Smb2CommandName.Logoff:
                {
                    if (structureSize == LogoffResponse.DeclaredSize)
                        return new LogoffResponse(buffer, offset);
                    if (structureSize == ErrorResponse.DeclaredSize)
                        return new ErrorResponse(buffer, offset);
                    throw new InvalidDataException();
                }
                case Smb2CommandName.TreeConnect:
                {
                    if (structureSize == TreeConnectResponse.DeclaredSize)
                        return new TreeConnectResponse(buffer, offset);
                    if (structureSize == ErrorResponse.DeclaredSize)
                        return new ErrorResponse(buffer, offset);
                    throw new InvalidDataException();
                }
                case Smb2CommandName.TreeDisconnect:
                {
                    if (structureSize == TreeDisconnectResponse.DeclaredSize)
                        return new TreeDisconnectResponse(buffer, offset);
                    if (structureSize == ErrorResponse.DeclaredSize)
                        return new ErrorResponse(buffer, offset);
                    throw new InvalidDataException();
                }
                case Smb2CommandName.Create:
                {
                    if (structureSize == CreateResponse.DeclaredSize)
                        return new CreateResponse(buffer, offset);
                    if (structureSize == ErrorResponse.DeclaredSize)
                        return new ErrorResponse(buffer, offset);
                    throw new InvalidDataException();
                }
                case Smb2CommandName.Close:
                {
                    if (structureSize == CloseResponse.DeclaredSize)
                        return new CloseResponse(buffer, offset);
                    if (structureSize == ErrorResponse.DeclaredSize)
                        return new ErrorResponse(buffer, offset);
                    throw new InvalidDataException();
                }
                case Smb2CommandName.Flush:
                {
                    if (structureSize == FlushResponse.DeclaredSize)
                        return new FlushResponse(buffer, offset);
                    if (structureSize == ErrorResponse.DeclaredSize)
                        return new ErrorResponse(buffer, offset);
                    throw new InvalidDataException();
                }
                case Smb2CommandName.Read:
                {
                    if (structureSize == Commands.ReadResponse.DeclaredSize)
                        return new ReadResponse(buffer, offset);
                    if (structureSize == ErrorResponse.DeclaredSize)
                        return new ErrorResponse(buffer, offset);
                    throw new InvalidDataException();
                }
                case Smb2CommandName.Write:
                {
                    if (structureSize == WriteResponse.DeclaredSize)
                        return new WriteResponse(buffer, offset);
                    if (structureSize == ErrorResponse.DeclaredSize)
                        return new ErrorResponse(buffer, offset);
                    throw new InvalidDataException();
                }
                case Smb2CommandName.Lock:
                {
                    if (structureSize == LockResponse.DeclaredSize)
                        return new LockResponse(buffer, offset);
                    if (structureSize == ErrorResponse.DeclaredSize)
                        return new ErrorResponse(buffer, offset);
                    throw new InvalidDataException();
                }
                case Smb2CommandName.IoCtl:
                {
                    if (structureSize == IoCtlResponse.DeclaredSize)
                        return new IoCtlResponse(buffer, offset);
                    if (structureSize == ErrorResponse.DeclaredSize)
                        return new ErrorResponse(buffer, offset);
                    throw new InvalidDataException();
                }
                case Smb2CommandName.Cancel:
                {
                    if (structureSize == ErrorResponse.DeclaredSize)
                        return new ErrorResponse(buffer, offset);
                    throw new InvalidDataException();
                }
                case Smb2CommandName.Echo:
                {
                    if (structureSize == EchoResponse.DeclaredSize)
                        return new EchoResponse(buffer, offset);
                    if (structureSize == ErrorResponse.DeclaredSize)
                        return new ErrorResponse(buffer, offset);
                    throw new InvalidDataException();
                }
                case Smb2CommandName.QueryDirectory:
                {
                    // QUERY_DIRECTORY Response and ERROR Response have the same declared StructureSize of 9.
                    if (structureSize == QueryDirectoryResponse.DeclaredSize)
                    {
                        var status = (NtStatus) LittleEndianConverter.ToUInt32(buffer, offset + 8);
                        if (status == NtStatus.StatusSuccess)
                            return new QueryDirectoryResponse(buffer, offset);
                        return new ErrorResponse(buffer, offset);
                    }

                    throw new InvalidDataException();
                }
                case Smb2CommandName.ChangeNotify:
                {
                    // CHANGE_NOTIFY Response and ERROR Response have the same declared StructureSize of 9.
                    if (structureSize == ChangeNotifyResponse.DeclaredSize)
                    {
                        var status = (NtStatus) LittleEndianConverter.ToUInt32(buffer, offset + 8);
                        if (status == NtStatus.StatusSuccess ||
                            status == NtStatus.StatusNotifyCleanup ||
                            status == NtStatus.StatusNotifyEnumDir)
                            return new ChangeNotifyResponse(buffer, offset);
                        return new ErrorResponse(buffer, offset);
                    }

                    throw new InvalidDataException();
                }
                case Smb2CommandName.QueryInfo:
                {
                    // QUERY_INFO Response and ERROR Response have the same declared StructureSize of 9.
                    if (structureSize == QueryInfoResponse.DeclaredSize)
                    {
                        var status = (NtStatus) LittleEndianConverter.ToUInt32(buffer, offset + 8);
                        if (status == NtStatus.StatusSuccess || status == NtStatus.StatusBufferOverflow)
                            return new QueryInfoResponse(buffer, offset);
                        return new ErrorResponse(buffer, offset);
                    }

                    throw new InvalidDataException();
                }
                case Smb2CommandName.SetInfo:
                {
                    if (structureSize == SetInfoResponse.DeclaredSize)
                        return new SetInfoResponse(buffer, offset);
                    if (structureSize == ErrorResponse.DeclaredSize)
                        return new ErrorResponse(buffer, offset);
                    throw new InvalidDataException();
                }
                default:
                    throw new InvalidDataException("Invalid SMB2 command 0x" + ((ushort) commandName).ToString("X4"));
            }
        }

        public static List<Smb2Command> ReadResponseChain(byte[] buffer, int offset)
        {
            var result = new List<Smb2Command>();
            Smb2Command command;
            do
            {
                command = ReadResponse(buffer, offset);
                result.Add(command);
                offset += (int) command.Header.NextCommand;
            } while (command.Header.NextCommand != 0);

            return result;
        }
    }
}