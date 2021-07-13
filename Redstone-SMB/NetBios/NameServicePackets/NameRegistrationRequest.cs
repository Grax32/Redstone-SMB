/* Copyright (C) 2014-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.IO;
using System.Net;
using RedstoneSmb.NetBios.NameServicePackets.Enums;
using RedstoneSmb.NetBios.NameServicePackets.EnumStructures;
using RedstoneSmb.NetBios.NameServicePackets.Structures;
using BigEndianWriter = RedstoneSmb.Utilities.ByteUtils.BigEndianWriter;
using ByteWriter = RedstoneSmb.Utilities.ByteUtils.ByteWriter;

namespace RedstoneSmb.NetBios.NameServicePackets
{
    /// <summary>
    ///     [RFC 1002] 4.2.2. NAME REGISTRATION REQUEST
    /// </summary>
    public class NameRegistrationRequest
    {
        public const int DataLength = 6;
        public byte[] Address; // IPv4 address

        public NameServicePacketHeader Header;
        public NameFlags NameFlags;
        public QuestionSection Question;
        public ResourceRecord Resource;

        public NameRegistrationRequest()
        {
            Header = new NameServicePacketHeader();
            Header.OpCode = NameServiceOperation.RegistrationRequest;
            Header.QdCount = 1;
            Header.ArCount = 1;
            Header.Flags = OperationFlags.Broadcast | OperationFlags.RecursionDesired;
            Question = new QuestionSection();
            Resource = new ResourceRecord(NameRecordType.Nb);
            Address = new byte[4];
        }

        public NameRegistrationRequest(string machineName, NetBiosSuffix suffix, IPAddress address) : this()
        {
            Question.Name = NetBiosUtils.GetMsNetBiosName(machineName, suffix);
            Address = address.GetAddressBytes();
        }

        public byte[] GetBytes()
        {
            Resource.Data = GetData();

            var stream = new MemoryStream();
            Header.WriteBytes(stream);
            Question.WriteBytes(stream);
            Resource.WriteBytes(stream, NameServicePacketHeader.Length);
            return stream.ToArray();
        }

        private byte[] GetData()
        {
            var data = new byte[DataLength];
            BigEndianWriter.WriteUInt16(data, 0, (ushort) NameFlags);
            ByteWriter.WriteBytes(data, 2, Address, 4);
            return data;
        }
    }
}