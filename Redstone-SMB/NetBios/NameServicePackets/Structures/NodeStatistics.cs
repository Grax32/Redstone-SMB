/* Copyright (C) 2014-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using BigEndianReader = RedstoneSmb.Utilities.ByteUtils.BigEndianReader;
using BigEndianWriter = RedstoneSmb.Utilities.ByteUtils.BigEndianWriter;
using ByteReader = RedstoneSmb.Utilities.ByteUtils.ByteReader;
using ByteWriter = RedstoneSmb.Utilities.ByteUtils.ByteWriter;

namespace RedstoneSmb.NetBios.NameServicePackets.Structures
{
    public class NodeStatistics
    {
        public const int Length = 46;
        public byte Jumpers;
        public ushort MaxNumberOfPendingSessions;
        public ushort MaxTotalNumberOfCommandBlocks;
        public ushort MaxTotalsSessionsPossible;
        public ushort NumberOfAlignmentErrors;
        public ushort NumberOfCollisions;
        public ushort NumberOfCrCs;
        public ushort NumberOfFreeCommandBlocks;
        public uint NumberOfGoodReceives;
        public uint NumberOfGoodSends;
        public ushort NumberOfNoResourceConditions;
        public ushort NumberOfPendingSessions;
        public ushort NumberOfRetransmits;
        public ushort NumberOfSendAborts;
        public ushort PeriodOfStatistics;
        public ushort SessionDataPacketSize;
        public byte TestResult;
        public ushort TotalNumberOfCommandBlocks;

        public byte[] UnitId; // MAC address, 6 bytes;
        public ushort VersionNumber;

        public NodeStatistics()
        {
            UnitId = new byte[6];
        }

        public NodeStatistics(byte[] buffer, ref int offset)
        {
            UnitId = ByteReader.ReadBytes(buffer, ref offset, 6);
            Jumpers = ByteReader.ReadByte(buffer, ref offset);
            TestResult = ByteReader.ReadByte(buffer, ref offset);
            VersionNumber = BigEndianReader.ReadUInt16(buffer, ref offset);
            PeriodOfStatistics = BigEndianReader.ReadUInt16(buffer, ref offset);
            NumberOfCrCs = BigEndianReader.ReadUInt16(buffer, ref offset);
            NumberOfAlignmentErrors = BigEndianReader.ReadUInt16(buffer, ref offset);
            NumberOfCollisions = BigEndianReader.ReadUInt16(buffer, ref offset);
            NumberOfSendAborts = BigEndianReader.ReadUInt16(buffer, ref offset);
            NumberOfGoodSends = BigEndianReader.ReadUInt16(buffer, ref offset);
            NumberOfGoodReceives = BigEndianReader.ReadUInt16(buffer, ref offset);
            NumberOfRetransmits = BigEndianReader.ReadUInt16(buffer, ref offset);
            NumberOfNoResourceConditions = BigEndianReader.ReadUInt16(buffer, ref offset);
            NumberOfFreeCommandBlocks = BigEndianReader.ReadUInt16(buffer, ref offset);
            TotalNumberOfCommandBlocks = BigEndianReader.ReadUInt16(buffer, ref offset);
            MaxTotalNumberOfCommandBlocks = BigEndianReader.ReadUInt16(buffer, ref offset);
            NumberOfPendingSessions = BigEndianReader.ReadUInt16(buffer, ref offset);
            MaxNumberOfPendingSessions = BigEndianReader.ReadUInt16(buffer, ref offset);
            MaxTotalsSessionsPossible = BigEndianReader.ReadUInt16(buffer, ref offset);
            SessionDataPacketSize = BigEndianReader.ReadUInt16(buffer, ref offset);
        }

        public void WriteBytes(byte[] buffer, int offset)
        {
            ByteWriter.WriteBytes(buffer, ref offset, UnitId, 6);
            ByteWriter.WriteByte(buffer, ref offset, Jumpers);
            ByteWriter.WriteByte(buffer, ref offset, TestResult);
            BigEndianWriter.WriteUInt16(buffer, ref offset, VersionNumber);
            BigEndianWriter.WriteUInt16(buffer, ref offset, PeriodOfStatistics);
            BigEndianWriter.WriteUInt16(buffer, ref offset, NumberOfCrCs);
            BigEndianWriter.WriteUInt16(buffer, ref offset, NumberOfAlignmentErrors);
            BigEndianWriter.WriteUInt16(buffer, ref offset, NumberOfCollisions);
            BigEndianWriter.WriteUInt16(buffer, ref offset, NumberOfSendAborts);
            BigEndianWriter.WriteUInt32(buffer, ref offset, NumberOfGoodSends);
            BigEndianWriter.WriteUInt32(buffer, ref offset, NumberOfGoodReceives);
            BigEndianWriter.WriteUInt16(buffer, ref offset, NumberOfRetransmits);
            BigEndianWriter.WriteUInt16(buffer, ref offset, NumberOfNoResourceConditions);
            BigEndianWriter.WriteUInt16(buffer, ref offset, NumberOfFreeCommandBlocks);
            BigEndianWriter.WriteUInt16(buffer, ref offset, TotalNumberOfCommandBlocks);
            BigEndianWriter.WriteUInt16(buffer, ref offset, MaxTotalNumberOfCommandBlocks);
            BigEndianWriter.WriteUInt16(buffer, ref offset, NumberOfPendingSessions);
            BigEndianWriter.WriteUInt16(buffer, ref offset, MaxNumberOfPendingSessions);
            BigEndianWriter.WriteUInt16(buffer, ref offset, MaxTotalsSessionsPossible);
            BigEndianWriter.WriteUInt16(buffer, ref offset, SessionDataPacketSize);
        }

        public byte[] GetBytes()
        {
            var buffer = new byte[Length];
            WriteBytes(buffer, 0);
            return buffer;
        }
    }
}