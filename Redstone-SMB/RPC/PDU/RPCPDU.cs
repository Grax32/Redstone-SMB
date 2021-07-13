/* Copyright (C) 2014-2018 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using RedstoneSmb.RPC.Enums;
using RedstoneSmb.RPC.EnumStructures;
using ByteReader = RedstoneSmb.Utilities.ByteUtils.ByteReader;
using ByteWriter = RedstoneSmb.Utilities.ByteUtils.ByteWriter;
using LittleEndianConverter = RedstoneSmb.Utilities.Conversion.LittleEndianConverter;
using LittleEndianWriter = RedstoneSmb.Utilities.ByteUtils.LittleEndianWriter;

namespace RedstoneSmb.RPC.PDU
{
    /// <summary>
    ///     See DCE 1.1: Remote Procedure Call, Chapter 12.6 - Connection-oriented RPC PDUs
    /// </summary>
    public abstract class Rpcpdu
    {
        public const int CommonFieldsLength = 16;
        public ushort AuthLength;
        public uint CallId;
        public DataRepresentationFormat DataRepresentation;
        public PacketFlags Flags;
        protected ushort FragmentLength; // The length of the entire PDU
        protected PacketTypeName PacketType;

        // The common header fields, which appear in all (connection oriented) PDU types:
        public byte VersionMajor; // rpc_vers
        public byte VersionMinor; // rpc_vers_minor

        public Rpcpdu()
        {
            VersionMajor = 5;
            VersionMinor = 0;
        }

        public Rpcpdu(byte[] buffer, int offset)
        {
            VersionMajor = ByteReader.ReadByte(buffer, offset + 0);
            VersionMinor = ByteReader.ReadByte(buffer, offset + 1);
            PacketType = (PacketTypeName) ByteReader.ReadByte(buffer, offset + 2);
            Flags = (PacketFlags) ByteReader.ReadByte(buffer, offset + 3);
            DataRepresentation = new DataRepresentationFormat(buffer, offset + 4);
            FragmentLength = LittleEndianConverter.ToUInt16(buffer, offset + 8);
            AuthLength = LittleEndianConverter.ToUInt16(buffer, offset + 10);
            CallId = LittleEndianConverter.ToUInt32(buffer, offset + 12);
        }

        /// <summary>
        ///     The length of the entire PDU
        /// </summary>
        public abstract int Length { get; }

        public abstract byte[] GetBytes();

        public void WriteCommonFieldsBytes(byte[] buffer)
        {
            ByteWriter.WriteByte(buffer, 0, VersionMajor);
            ByteWriter.WriteByte(buffer, 1, VersionMinor);
            ByteWriter.WriteByte(buffer, 2, (byte) PacketType);
            ByteWriter.WriteByte(buffer, 3, (byte) Flags);
            DataRepresentation.WriteBytes(buffer, 4);
            LittleEndianWriter.WriteUInt16(buffer, 8, (ushort) Length);
            LittleEndianWriter.WriteUInt16(buffer, 10, AuthLength);
            LittleEndianWriter.WriteUInt32(buffer, 12, CallId);
        }

        public static Rpcpdu GetPdu(byte[] buffer, int offset)
        {
            var packetType = (PacketTypeName) ByteReader.ReadByte(buffer, 2);
            switch (packetType)
            {
                case PacketTypeName.Request:
                    return new RequestPdu(buffer, offset);
                case PacketTypeName.Response:
                    return new ResponsePdu(buffer, offset);
                case PacketTypeName.Fault:
                    return new FaultPdu(buffer, offset);
                case PacketTypeName.Bind:
                    return new BindPdu(buffer, offset);
                case PacketTypeName.BindAck:
                    return new BindAckPdu(buffer, offset);
                case PacketTypeName.BindNak:
                    return new BindNakPdu(buffer, offset);
                default:
                    throw new NotImplementedException();
            }
        }

        public static ushort GetPduLength(byte[] buffer, int offset)
        {
            var fragmentLength = LittleEndianConverter.ToUInt16(buffer, offset + 8);
            return fragmentLength;
        }
    }
}