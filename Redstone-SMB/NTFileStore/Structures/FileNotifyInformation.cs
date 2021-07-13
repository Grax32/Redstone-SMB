/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Collections.Generic;
using ByteReader = RedstoneSmb.Utilities.ByteUtils.ByteReader;
using ByteWriter = RedstoneSmb.Utilities.ByteUtils.ByteWriter;
using LittleEndianConverter = RedstoneSmb.Utilities.Conversion.LittleEndianConverter;
using LittleEndianWriter = RedstoneSmb.Utilities.ByteUtils.LittleEndianWriter;

namespace RedstoneSmb.NTFileStore.Structures
{
    public enum FileAction : uint
    {
        Added = 0x00000001, // FILE_ACTION_ADDED
        Removed = 0x00000002, // FILE_ACTION_REMOVED
        Modified = 0x00000003, // FILE_ACTION_MODIFIED
        RenamedOldName = 0x00000004, // FILE_ACTION_RENAMED_OLD_NAME
        RenamedNewName = 0x00000005, // FILE_ACTION_RENAMED_NEW_NAME
        AddedStream = 0x00000006, // FILE_ACTION_ADDED_STREAM
        RemovedStream = 0x00000007, // FILE_ACTION_REMOVED_STREAM
        ModifiedStream = 0x00000008, // FILE_ACTION_MODIFIED_STREAM
        RemovedByDelete = 0x00000009, // FILE_ACTION_REMOVED_BY_DELETE
        IdNotTunneled = 0x0000000A, // FILE_ACTION_ID_NOT_TUNNELLED
        TunneledIdCollision = 0x0000000B // FILE_ACTION_TUNNELLED_ID_COLLISION
    }

    /// <summary>
    ///     [MS-FSCC] 2.4.42 - FileNotifyInformation
    /// </summary>
    public class FileNotifyInformation
    {
        public const int FixedLength = 12;
        public FileAction Action;
        public string FileName;
        private uint _fileNameLength;

        public uint NextEntryOffset;

        public FileNotifyInformation()
        {
            FileName = string.Empty;
        }

        public FileNotifyInformation(byte[] buffer, int offset)
        {
            NextEntryOffset = LittleEndianConverter.ToUInt32(buffer, offset + 0);
            Action = (FileAction) LittleEndianConverter.ToUInt32(buffer, offset + 4);
            _fileNameLength = LittleEndianConverter.ToUInt32(buffer, offset + 8);
            FileName = ByteReader.ReadUtf16String(buffer, offset + 12, (int) (_fileNameLength / 2));
        }

        public int Length => FixedLength + FileName.Length * 2;

        public void WriteBytes(byte[] buffer, int offset)
        {
            _fileNameLength = (uint) (FileName.Length * 2);
            LittleEndianWriter.WriteUInt32(buffer, offset + 0, NextEntryOffset);
            LittleEndianWriter.WriteUInt32(buffer, offset + 4, (uint) Action);
            LittleEndianWriter.WriteUInt32(buffer, offset + 8, _fileNameLength);
            ByteWriter.WriteUtf16String(buffer, offset + 12, FileName);
        }

        public static List<FileNotifyInformation> ReadList(byte[] buffer, int offset)
        {
            var result = new List<FileNotifyInformation>();
            FileNotifyInformation entry;
            do
            {
                entry = new FileNotifyInformation(buffer, offset);
                result.Add(entry);
                offset += (int) entry.NextEntryOffset;
            } while (entry.NextEntryOffset != 0);

            return result;
        }

        public static byte[] GetBytes(List<FileNotifyInformation> notifyInformationList)
        {
            var listLength = GetListLength(notifyInformationList);
            var buffer = new byte[listLength];
            var offset = 0;
            for (var index = 0; index < notifyInformationList.Count; index++)
            {
                var entry = notifyInformationList[index];
                var length = entry.Length;
                var paddedLength = (int) Math.Ceiling((double) length / 4) * 4;
                if (index < notifyInformationList.Count - 1)
                    entry.NextEntryOffset = (uint) paddedLength;
                else
                    entry.NextEntryOffset = 0;
                entry.WriteBytes(buffer, offset);
                offset += paddedLength;
            }

            return buffer;
        }

        public static int GetListLength(List<FileNotifyInformation> notifyInformationList)
        {
            var result = 0;
            for (var index = 0; index < notifyInformationList.Count; index++)
            {
                var entry = notifyInformationList[index];
                var length = entry.Length;
                // [MS-FSCC] NextEntryOffset MUST always be an integral multiple of 4.
                // The FileName array MUST be padded to the next 4-byte boundary counted from the beginning of the structure.
                if (index < notifyInformationList.Count - 1)
                {
                    // No padding is required following the last data element.
                    var paddedLength = (int) Math.Ceiling((double) length / 4) * 4;
                    result += paddedLength;
                }
                else
                {
                    result += length;
                }
            }

            return result;
        }
    }
}