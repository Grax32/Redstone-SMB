/* Copyright (C) 2014-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.IO;
using RedstoneSmb.NetBios.SessionPackets;
using ByteReader = RedstoneSmb.Utilities.ByteUtils.ByteReader;

namespace RedstoneSmb.NetBios
{
    public class NbtConnectionReceiveBuffer
    {
        private int? _mPacketLength;
        private int _mReadOffset;

        public NbtConnectionReceiveBuffer() : this(SessionPacket.MaxSessionPacketLength)
        {
        }

        /// <param name="bufferLength">Must be large enough to hold the largest possible NBT packet</param>
        public NbtConnectionReceiveBuffer(int bufferLength)
        {
            if (bufferLength < SessionPacket.MaxSessionPacketLength)
                throw new ArgumentException(
                    "bufferLength must be large enough to hold the largest possible NBT packet");
            Buffer = new byte[bufferLength];
        }

        public byte[] Buffer { get; private set; }

        public int WriteOffset => _mReadOffset + BytesInBuffer;

        public int BytesInBuffer { get; private set; }

        public int AvailableLength => Buffer.Length - (_mReadOffset + BytesInBuffer);

        public void IncreaseBufferSize(int bufferLength)
        {
            var buffer = new byte[bufferLength];
            if (BytesInBuffer > 0)
            {
                Array.Copy(Buffer, _mReadOffset, buffer, 0, BytesInBuffer);
                _mReadOffset = 0;
            }

            Buffer = buffer;
        }

        public void SetNumberOfBytesReceived(int numberOfBytesReceived)
        {
            BytesInBuffer += numberOfBytesReceived;
        }

        public bool HasCompletePacket()
        {
            if (BytesInBuffer >= 4)
            {
                if (!_mPacketLength.HasValue)
                    _mPacketLength = SessionPacket.GetSessionPacketLength(Buffer, _mReadOffset);

                return BytesInBuffer >= _mPacketLength.Value;
            }

            return false;
        }

        /// <summary>
        ///     HasCompletePacket must be called and return true before calling DequeuePacket
        /// </summary>
        /// <exception cref="System.IO.InvalidDataException"></exception>
        public SessionPacket DequeuePacket()
        {
            SessionPacket packet;
            try
            {
                packet = SessionPacket.GetSessionPacket(Buffer, _mReadOffset);
            }
            catch (IndexOutOfRangeException ex)
            {
                throw new InvalidDataException("Invalid NetBIOS session packet", ex);
            }

            RemovePacketBytes();
            return packet;
        }

        /// <summary>
        ///     HasCompletePDU must be called and return true before calling DequeuePDUBytes
        /// </summary>
        public byte[] DequeuePacketBytes()
        {
            var packetBytes = ByteReader.ReadBytes(Buffer, _mReadOffset, _mPacketLength.Value);
            RemovePacketBytes();
            return packetBytes;
        }

        private void RemovePacketBytes()
        {
            BytesInBuffer -= _mPacketLength.Value;
            if (BytesInBuffer == 0)
            {
                _mReadOffset = 0;
                _mPacketLength = null;
            }
            else
            {
                _mReadOffset += _mPacketLength.Value;
                _mPacketLength = null;
                if (!HasCompletePacket())
                {
                    Array.Copy(Buffer, _mReadOffset, Buffer, 0, BytesInBuffer);
                    _mReadOffset = 0;
                }
            }
        }
    }
}