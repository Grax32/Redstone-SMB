/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using LittleEndianConverter = RedstoneSmb.Utilities.Conversion.LittleEndianConverter;
using LittleEndianWriter = RedstoneSmb.Utilities.ByteUtils.LittleEndianWriter;

namespace RedstoneSmb.RPC.Structures
{
    /// <summary>
    ///     p_syntax_id_t
    /// </summary>
    public struct SyntaxId
    {
        public const int Length = 20;

        public Guid InterfaceUuid; // if_uuid
        public uint InterfaceVersion; // if_version

        public SyntaxId(Guid interfaceUuid, uint interfaceVersion)
        {
            InterfaceUuid = interfaceUuid;
            InterfaceVersion = interfaceVersion;
        }

        public SyntaxId(byte[] buffer, int offset)
        {
            InterfaceUuid = LittleEndianConverter.ToGuid(buffer, offset + 0);
            InterfaceVersion = LittleEndianConverter.ToUInt32(buffer, offset + 16);
        }

        public void WriteBytes(byte[] buffer, int offset)
        {
            LittleEndianWriter.WriteGuid(buffer, offset + 0, InterfaceUuid);
            LittleEndianWriter.WriteUInt32(buffer, offset + 16, InterfaceVersion);
        }

        public override bool Equals(object obj)
        {
            if (obj is SyntaxId)
                return InterfaceUuid.Equals(((SyntaxId) obj).InterfaceUuid) &&
                       InterfaceVersion.Equals(((SyntaxId) obj).InterfaceVersion);
            return false;
        }

        public override int GetHashCode()
        {
            return InterfaceUuid.GetHashCode() * InterfaceVersion.GetHashCode();
        }
    }
}