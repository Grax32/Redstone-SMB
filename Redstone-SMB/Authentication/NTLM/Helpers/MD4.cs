/* Copyright (C) 1990-2, RSA Data Security, Inc. All rights reserved.

   License to copy and use this software is granted provided that it
   is identified as the "RSA Data Security, Inc. MD4 Message-Digest
   Algorithm" in all material mentioning or referencing this software
   or this function.

   License is also granted to make and use derivative works provided
   that such works are identified as "derived from the RSA Data
   Security, Inc. MD4 Message-Digest Algorithm" in all material
   mentioning or referencing the derived work.

   RSA Data Security, Inc. makes no representations concerning either
   the merchantability of this software or the suitability of this
   software for any particular purpose. It is provided "as is"
   without express or implied warranty of any kind.


   --------------------------------------------------------------

   Ported from Norbert Hranitzky's (norbert.hranitzky@mchp.siemens.de)
   Java version by Oren Novotny (osn@po.cwru.edu)

   --------------------------------------------------------------
   Adapted to C# 2.0 By Tal Aloni
   --------------------------------------------------------------


*/

using System;
using System.Text;

namespace RedstoneSmb.Authentication.NTLM.Helpers
{
    /// <summary>
    ///     Implements the MD4 message digest algorithm in C#
    /// </summary>
    /// <remarks>
    ///     <p>
    ///         <b>References:</b>
    ///         <ol>
    ///             <li>
    ///                 Ronald L. Rivest,
    ///                 "
    ///                 <a href="http://www.roxen.com/rfc/rfc1320.html">
    ///                     The MD4 Message-Digest Algorithm
    ///                 </a>
    ///                 ",
    ///                 IETF RFC-1320 (informational).
    ///             </li>
    ///         </ol>
    ///     </p>
    /// </remarks>
    public class Md4
    {
        // MD4 specific object variables
        //-----------------------------------------------------------------------

        /// <summary>
        ///     The size in bytes of the input block to the transformation algorithm
        /// </summary>
        private const int BlockLength = 64; // = 512 / 8

        /// <summary>
        ///     4 32-bit words (interim result)
        /// </summary>
        private readonly uint[] _context = new uint[4];

        /// <summary>
        ///     512-bit work buffer = 16 x 32-bit words
        /// </summary>
        private readonly uint[] _x = new uint[16];

        /// <summary>
        ///     512-bit input buffer = 16 x 32-bit words holds until it reaches 512 bits
        /// </summary>
        private byte[] _buffer = new byte[BlockLength];

        /// <summary>
        ///     Number of bytes procesed so far mod. 2 power of 64.
        /// </summary>
        private long _count;


        // Constructors
        //------------------------------------------------------------------------
        public Md4()
        {
            EngineReset();
        }

        /// <summary>
        ///     This constructor is here to implement the clonability of this class
        /// </summary>
        /// <param name="md"> </param>
        private Md4(Md4 md)
            : this()
        {
            //this();
            _context = (uint[]) md._context.Clone();
            _buffer = (byte[]) md._buffer.Clone();
            _count = md._count;
        }

        // Clonable method implementation
        //-------------------------------------------------------------------------
        public object Clone()
        {
            return new Md4(this);
        }

        // JCE methods
        //-------------------------------------------------------------------------

        /// <summary>
        ///     Resets this object disregarding any temporary data present at the
        ///     time of the invocation of this call.
        /// </summary>
        private void EngineReset()
        {
            // initial values of MD4 i.e. A, B, C, D
            // as per rfc-1320; they are low-order byte first
            _context[0] = 0x67452301;
            _context[1] = 0xEFCDAB89;
            _context[2] = 0x98BADCFE;
            _context[3] = 0x10325476;
            _count = 0L;
            for (var i = 0; i < BlockLength; i++)
                _buffer[i] = 0;
        }


        /// <summary>
        ///     Continues an MD4 message digest using the input byte
        /// </summary>
        /// <param name="b">byte to input</param>
        private void EngineUpdate(byte b)
        {
            // compute number of bytes still unhashed; ie. present in buffer
            var i = (int) (_count % BlockLength);
            _count++; // update number of bytes
            _buffer[i] = b;
            if (i == BlockLength - 1)
                Transform(ref _buffer, 0);
        }

        /// <summary>
        ///     MD4 block update operation
        /// </summary>
        /// <remarks>
        ///     Continues an MD4 message digest operation by filling the buffer,
        ///     transform(ing) data in 512-bit message block(s), updating the variables
        ///     context and count, and leaving (buffering) the remaining bytes in buffer
        ///     for the next update or finish.
        /// </remarks>
        /// <param name="input">input block</param>
        /// <param name="offset">start of meaningful bytes in input</param>
        /// <param name="len">count of bytes in input blcok to consider</param>
        private void EngineUpdate(byte[] input, int offset, int len)
        {
            // make sure we don't exceed input's allocated size/length
            if (offset < 0 || len < 0 || (long) offset + len > input.Length)
                throw new ArgumentOutOfRangeException();

            // compute number of bytes still unhashed; ie. present in buffer
            var bufferNdx = (int) (_count % BlockLength);
            _count += len; // update number of bytes
            var partLen = BlockLength - bufferNdx;
            var i = 0;
            if (len >= partLen)
            {
                Array.Copy(input, offset + i, _buffer, bufferNdx, partLen);

                Transform(ref _buffer, 0);

                for (i = partLen; i + BlockLength - 1 < len; i += BlockLength)
                    Transform(ref input, offset + i);
                bufferNdx = 0;
            }

            // buffer remaining input
            if (i < len)
                Array.Copy(input, offset + i, _buffer, bufferNdx, len - i);
        }

        /// <summary>
        ///     Completes the hash computation by performing final operations such
        ///     as padding.  At the return of this engineDigest, the MD engine is
        ///     reset.
        /// </summary>
        /// <returns>the array of bytes for the resulting hash value.</returns>
        private byte[] EngineDigest()
        {
            // pad output to 56 mod 64; as RFC1320 puts it: congruent to 448 mod 512
            var bufferNdx = (int) (_count % BlockLength);
            var padLen = bufferNdx < 56 ? 56 - bufferNdx : 120 - bufferNdx;

            // padding is always binary 1 followed by binary 0's
            var tail = new byte[padLen + 8];
            tail[0] = 0x80;

            // append length before final transform
            // save number of bits, casting the long to an array of 8 bytes
            // save low-order byte first.
            for (var i = 0; i < 8; i++)
                tail[padLen + i] = (byte) ((_count * 8) >> (8 * i));

            EngineUpdate(tail, 0, tail.Length);

            var result = new byte[16];
            // cast this MD4's context (array of 4 uints) into an array of 16 bytes.
            for (var i = 0; i < 4; i++)
            for (var j = 0; j < 4; j++)
                result[i * 4 + j] = (byte) (_context[i] >> (8 * j));

            // reset the engine
            EngineReset();
            return result;
        }

        /// <summary>
        ///     Returns a byte hash from a string
        /// </summary>
        /// <param name="s">string to hash</param>
        /// <returns>byte-array that contains the hash</returns>
        public byte[] GetByteHashFromString(string s)
        {
            var b = Encoding.UTF8.GetBytes(s);
            var md4 = new Md4();

            md4.EngineUpdate(b, 0, b.Length);

            return md4.EngineDigest();
        }

        /// <summary>
        ///     Returns a binary hash from an input byte array
        /// </summary>
        /// <param name="b">byte-array to hash</param>
        /// <returns>binary hash of input</returns>
        public byte[] GetByteHashFromBytes(byte[] b)
        {
            var md4 = new Md4();

            md4.EngineUpdate(b, 0, b.Length);

            return md4.EngineDigest();
        }

        /// <summary>
        ///     Returns a string that contains the hexadecimal hash
        /// </summary>
        /// <param name="b">byte-array to input</param>
        /// <returns>String that contains the hex of the hash</returns>
        public string GetHexHashFromBytes(byte[] b)
        {
            var e = GetByteHashFromBytes(b);
            return BytesToHex(e, e.Length);
        }

        /// <summary>
        ///     Returns a byte hash from the input byte
        /// </summary>
        /// <param name="b">byte to hash</param>
        /// <returns>binary hash of the input byte</returns>
        public byte[] GetByteHashFromByte(byte b)
        {
            var md4 = new Md4();

            md4.EngineUpdate(b);

            return md4.EngineDigest();
        }

        /// <summary>
        ///     Returns a string that contains the hexadecimal hash
        /// </summary>
        /// <param name="b">byte to hash</param>
        /// <returns>String that contains the hex of the hash</returns>
        public string GetHexHashFromByte(byte b)
        {
            var e = GetByteHashFromByte(b);
            return BytesToHex(e, e.Length);
        }

        /// <summary>
        ///     Returns a string that contains the hexadecimal hash
        /// </summary>
        /// <param name="s">string to hash</param>
        /// <returns>String that contains the hex of the hash</returns>
        public string GetHexHashFromString(string s)
        {
            var b = GetByteHashFromString(s);
            return BytesToHex(b, b.Length);
        }

        private static string BytesToHex(byte[] a, int len)
        {
            var temp = BitConverter.ToString(a);

            // We need to remove the dashes that come from the BitConverter
            var sb = new StringBuilder((len - 2) / 2); // This should be the final size

            for (var i = 0; i < temp.Length; i++)
                if (temp[i] != '-')
                    sb.Append(temp[i]);

            return sb.ToString();
        }

        // own methods
        //-----------------------------------------------------------------------------------

        /// <summary>
        ///     MD4 basic transformation
        /// </summary>
        /// <remarks>
        ///     Transforms context based on 512 bits from input block starting
        ///     from the offset'th byte.
        /// </remarks>
        /// <param name="block">input sub-array</param>
        /// <param name="offset">starting position of sub-array</param>
        private void Transform(ref byte[] block, int offset)
        {
            // decodes 64 bytes from input block into an array of 16 32-bit
            // entities. Use A as a temp var.
            for (var i = 0; i < 16; i++)
                _x[i] = ((uint) block[offset++] & 0xFF) |
                       (((uint) block[offset++] & 0xFF) << 8) |
                       (((uint) block[offset++] & 0xFF) << 16) |
                       (((uint) block[offset++] & 0xFF) << 24);


            var a = _context[0];
            var b = _context[1];
            var c = _context[2];
            var d = _context[3];

            a = Ff(a, b, c, d, _x[0], 3);
            d = Ff(d, a, b, c, _x[1], 7);
            c = Ff(c, d, a, b, _x[2], 11);
            b = Ff(b, c, d, a, _x[3], 19);
            a = Ff(a, b, c, d, _x[4], 3);
            d = Ff(d, a, b, c, _x[5], 7);
            c = Ff(c, d, a, b, _x[6], 11);
            b = Ff(b, c, d, a, _x[7], 19);
            a = Ff(a, b, c, d, _x[8], 3);
            d = Ff(d, a, b, c, _x[9], 7);
            c = Ff(c, d, a, b, _x[10], 11);
            b = Ff(b, c, d, a, _x[11], 19);
            a = Ff(a, b, c, d, _x[12], 3);
            d = Ff(d, a, b, c, _x[13], 7);
            c = Ff(c, d, a, b, _x[14], 11);
            b = Ff(b, c, d, a, _x[15], 19);

            a = Gg(a, b, c, d, _x[0], 3);
            d = Gg(d, a, b, c, _x[4], 5);
            c = Gg(c, d, a, b, _x[8], 9);
            b = Gg(b, c, d, a, _x[12], 13);
            a = Gg(a, b, c, d, _x[1], 3);
            d = Gg(d, a, b, c, _x[5], 5);
            c = Gg(c, d, a, b, _x[9], 9);
            b = Gg(b, c, d, a, _x[13], 13);
            a = Gg(a, b, c, d, _x[2], 3);
            d = Gg(d, a, b, c, _x[6], 5);
            c = Gg(c, d, a, b, _x[10], 9);
            b = Gg(b, c, d, a, _x[14], 13);
            a = Gg(a, b, c, d, _x[3], 3);
            d = Gg(d, a, b, c, _x[7], 5);
            c = Gg(c, d, a, b, _x[11], 9);
            b = Gg(b, c, d, a, _x[15], 13);

            a = Hh(a, b, c, d, _x[0], 3);
            d = Hh(d, a, b, c, _x[8], 9);
            c = Hh(c, d, a, b, _x[4], 11);
            b = Hh(b, c, d, a, _x[12], 15);
            a = Hh(a, b, c, d, _x[2], 3);
            d = Hh(d, a, b, c, _x[10], 9);
            c = Hh(c, d, a, b, _x[6], 11);
            b = Hh(b, c, d, a, _x[14], 15);
            a = Hh(a, b, c, d, _x[1], 3);
            d = Hh(d, a, b, c, _x[9], 9);
            c = Hh(c, d, a, b, _x[5], 11);
            b = Hh(b, c, d, a, _x[13], 15);
            a = Hh(a, b, c, d, _x[3], 3);
            d = Hh(d, a, b, c, _x[11], 9);
            c = Hh(c, d, a, b, _x[7], 11);
            b = Hh(b, c, d, a, _x[15], 15);

            _context[0] += a;
            _context[1] += b;
            _context[2] += c;
            _context[3] += d;
        }

        // The basic MD4 atomic functions.

        private uint Ff(uint a, uint b, uint c, uint d, uint x, int s)
        {
            var t = a + ((b & c) | (~b & d)) + x;
            return (t << s) | (t >> (32 - s));
        }

        private uint Gg(uint a, uint b, uint c, uint d, uint x, int s)
        {
            var t = a + ((b & (c | d)) | (c & d)) + x + 0x5A827999;
            return (t << s) | (t >> (32 - s));
        }

        private uint Hh(uint a, uint b, uint c, uint d, uint x, int s)
        {
            var t = a + (b ^ c ^ d) + x + 0x6ED9EBA1;
            return (t << s) | (t >> (32 - s));
        }
    }

    // class MD4
}

// namespace MD4Hash