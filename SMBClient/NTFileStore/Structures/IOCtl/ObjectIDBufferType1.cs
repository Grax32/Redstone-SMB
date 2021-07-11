/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using SMBLibrary.Utilities.ByteUtils;
using SMBLibrary.Utilities.Conversion;
using LittleEndianConverter = SMBLibrary.Utilities.Conversion.LittleEndianConverter;
using LittleEndianWriter = SMBLibrary.Utilities.ByteUtils.LittleEndianWriter;

namespace SMBLibrary.NTFileStore.Structures.IOCtl
{
    /// <summary>
    ///     [MS-FSCC] 2.1.3.1 - FILE_OBJECTID_BUFFER Type 1
    /// </summary>
    public class ObjectIDBufferType1
    {
        public const int Length = 64;
        public Guid BirthObjectId;
        public Guid BirthVolumeId;
        public Guid DomainId;

        public Guid ObjectId;

        public ObjectIDBufferType1()
        {
        }

        public ObjectIDBufferType1(byte[] buffer)
        {
            ObjectId = LittleEndianConverter.ToGuid(buffer, 0);
            BirthVolumeId = LittleEndianConverter.ToGuid(buffer, 16);
            BirthObjectId = LittleEndianConverter.ToGuid(buffer, 32);
            DomainId = LittleEndianConverter.ToGuid(buffer, 48);
        }

        public byte[] GetBytes()
        {
            var buffer = new byte[Length];
            LittleEndianWriter.WriteGuid(buffer, 0, ObjectId);
            LittleEndianWriter.WriteGuid(buffer, 16, BirthVolumeId);
            LittleEndianWriter.WriteGuid(buffer, 32, BirthObjectId);
            LittleEndianWriter.WriteGuid(buffer, 48, DomainId);
            return buffer;
        }
    }
}