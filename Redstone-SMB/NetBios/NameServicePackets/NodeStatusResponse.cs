/* Copyright (C) 2014-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.IO;
using RedstoneSmb.NetBios.NameServicePackets.Enums;
using RedstoneSmb.NetBios.NameServicePackets.EnumStructures;
using RedstoneSmb.NetBios.NameServicePackets.Structures;
using BigEndianReader = RedstoneSmb.Utilities.ByteUtils.BigEndianReader;
using BigEndianWriter = RedstoneSmb.Utilities.ByteUtils.BigEndianWriter;
using ByteReader = RedstoneSmb.Utilities.ByteUtils.ByteReader;
using ByteWriter = RedstoneSmb.Utilities.ByteUtils.ByteWriter;

namespace RedstoneSmb.NetBios.NameServicePackets
{
    /// <summary>
    ///     [RFC 1002] 4.2.18. NODE STATUS RESPONSE
    /// </summary>
    public class NodeStatusResponse
    {
        public NameServicePacketHeader Header;

        // Resource Data:
        // byte NumberOfNames;
        public Utilities.Generics.KeyValuePairList<string, NameFlags> Names = new Utilities.Generics.KeyValuePairList<string, NameFlags>();
        public ResourceRecord Resource;
        public NodeStatistics Statistics;

        public NodeStatusResponse()
        {
            Header = new NameServicePacketHeader();
            Header.OpCode = NameServiceOperation.QueryResponse;
            Header.Flags = OperationFlags.AuthoritativeAnswer | OperationFlags.RecursionAvailable;
            Header.AnCount = 1;
            Resource = new ResourceRecord(NameRecordType.NbStat);
            Statistics = new NodeStatistics();
        }

        public NodeStatusResponse(byte[] buffer, int offset)
        {
            Header = new NameServicePacketHeader(buffer, ref offset);
            Resource = new ResourceRecord(buffer, ref offset);

            var position = 0;
            var numberOfNames = ByteReader.ReadByte(Resource.Data, ref position);
            for (var index = 0; index < numberOfNames; index++)
            {
                var name = ByteReader.ReadAnsiString(Resource.Data, ref position, 16);
                var nameFlags = (NameFlags) BigEndianReader.ReadUInt16(Resource.Data, ref position);
                Names.Add(name, nameFlags);
            }

            Statistics = new NodeStatistics(Resource.Data, ref position);
        }

        public byte[] GetBytes()
        {
            Resource.Data = GetData();

            var stream = new MemoryStream();
            Header.WriteBytes(stream);
            Resource.WriteBytes(stream);
            return stream.ToArray();
        }

        private byte[] GetData()
        {
            var stream = new MemoryStream();
            stream.WriteByte((byte) Names.Count);
            foreach (var entry in Names)
            {
                ByteWriter.WriteAnsiString(stream, entry.Key);
                BigEndianWriter.WriteUInt16(stream, (ushort) entry.Value);
            }

            ByteWriter.WriteBytes(stream, Statistics.GetBytes());

            return stream.ToArray();
        }
    }
}