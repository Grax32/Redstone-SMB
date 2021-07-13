/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.NetBios.SessionPackets.Enums;
using SMBLibrary.Utilities.ByteUtils;
using ByteWriter = SMBLibrary.Utilities.ByteUtils.ByteWriter;

namespace SMBLibrary.NetBios.SessionPackets
{
    /// <summary>
    ///     [RFC 1002] 4.3.2. SESSION REQUEST PACKET
    /// </summary>
    public class SessionRequestPacket : SessionPacket
    {
        public SessionRequestPacket() : base()
        {
            Type = SessionPacketTypeName.SessionRequest;
        }

        public SessionRequestPacket(byte[] buffer, int offset) : base(buffer, offset)
        {
            CalledName = NetBiosUtils.DecodeName(Trailer, ref offset);
            CallingName = NetBiosUtils.DecodeName(Trailer, ref offset);
        }

        public override int Length
        {
            get
            {
                var part1 = NetBiosUtils.EncodeName(CalledName, string.Empty);
                var part2 = NetBiosUtils.EncodeName(CallingName, string.Empty);
                return HeaderLength + part1.Length + part2.Length;
            }
        }

        public string CalledName { get; set; }
        public string CallingName { get; set; }

        public override byte[] GetBytes()
        {
            var part1 = NetBiosUtils.EncodeName(CalledName, string.Empty);
            var part2 = NetBiosUtils.EncodeName(CallingName, string.Empty);
            Trailer = new byte[part1.Length + part2.Length];
            ByteWriter.WriteBytes(Trailer, 0, part1);
            ByteWriter.WriteBytes(Trailer, part1.Length, part2);
            return base.GetBytes();
        }
    }
}