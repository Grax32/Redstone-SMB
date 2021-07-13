/* Copyright (C) 2014-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.IO;
using RedstoneSmb.NetBios.SessionPackets.Enums;
using BigEndianConverter = RedstoneSmb.Utilities.Conversion.BigEndianConverter;
using BigEndianWriter = RedstoneSmb.Utilities.ByteUtils.BigEndianWriter;
using ByteReader = RedstoneSmb.Utilities.ByteUtils.ByteReader;
using ByteWriter = RedstoneSmb.Utilities.ByteUtils.ByteWriter;

namespace RedstoneSmb.NetBios.SessionPackets
{
    /// <summary>
    ///     [RFC 1002] 4.3.1. SESSION PACKET
    ///     [MS-SMB2] 2.1 Transport - Direct TCP transport packet
    /// </summary>
    /// <remarks>
    ///     We extend this implementation to support Direct TCP transport packet which utilize the unused session packet flags
    ///     to extend the maximum trailer length.
    /// </remarks>
    public abstract class SessionPacket
    {
        public const int HeaderLength = 4;
        public const int MaxSessionPacketLength = 131075;
        public const int MaxDirectTcpPacketLength = 16777215;
        public byte[] Trailer;
        private int _trailerLength; // Session packet: 17 bits, Direct TCP transport packet: 3 bytes

        public SessionPacketTypeName Type;

        protected SessionPacket() { }

        protected SessionPacket(byte[] buffer, int offset)
        {
            Type = (SessionPacketTypeName) ByteReader.ReadByte(buffer, offset + 0);
            _trailerLength = (ByteReader.ReadByte(buffer, offset + 1) << 16) |
                            BigEndianConverter.ToUInt16(buffer, offset + 2);
            Trailer = ByteReader.ReadBytes(buffer, offset + 4, _trailerLength);
        }

        public virtual int Length => HeaderLength + Trailer.Length;

        public virtual byte[] GetBytes()
        {
            _trailerLength = Trailer.Length;

            var flags = Convert.ToByte(_trailerLength >> 16);

            var buffer = new byte[HeaderLength + Trailer.Length];

            ByteWriter.WriteByte(buffer, 0, (byte) Type);
            ByteWriter.WriteByte(buffer, 1, flags);
            BigEndianWriter.WriteUInt16(buffer, 2, (ushort) (_trailerLength & 0xFFFF));
            ByteWriter.WriteBytes(buffer, 4, Trailer);

            return buffer;
        }

        public static int GetSessionPacketLength(byte[] buffer, int offset)
        {
            var trailerLength = (ByteReader.ReadByte(buffer, offset + 1) << 16) |
                                BigEndianConverter.ToUInt16(buffer, offset + 2);

            return 4 + trailerLength;
        }

        public static SessionPacket GetSessionPacket(byte[] buffer, int offset)
        {
            var type = (SessionPacketTypeName) ByteReader.ReadByte(buffer, offset);

            switch (type)
            {
                case SessionPacketTypeName.SessionMessage:
                    return new SessionMessagePacket(buffer, offset);
                case SessionPacketTypeName.SessionRequest:
                    return new SessionRequestPacket(buffer, offset);
                case SessionPacketTypeName.PositiveSessionResponse:
                    return new PositiveSessionResponsePacket(buffer, offset);
                case SessionPacketTypeName.NegativeSessionResponse:
                    return new NegativeSessionResponsePacket(buffer, offset);
                case SessionPacketTypeName.RetargetSessionResponse:
                    return new SessionRetargetResponsePacket(buffer, offset);
                case SessionPacketTypeName.SessionKeepAlive:
                    return new SessionKeepAlivePacket(buffer, offset);
                default:
                    throw new InvalidDataException("Invalid NetBIOS session packet type: 0x" +
                                                   ((byte) type).ToString("X2"));
            }
        }
    }
}