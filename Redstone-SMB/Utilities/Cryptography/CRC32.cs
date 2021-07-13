/* Author: Damien Guard (damieng@gmail.com)
 * http://damieng.com/blog/2006/08/08/calculating_crc32_in_c_and_net
 */

using System.Security.Cryptography;

namespace RedstoneSmb.Utilities.Cryptography
{
    public class Crc32 : HashAlgorithm
    {
        public const uint DefaultPolynomial = 0xedb88320;
        public const uint DefaultSeed = 0xffffffff;
        private static uint[] _defaultTable;

        private uint _hash;
        private readonly uint _seed;
        private readonly uint[] _table;

        public Crc32()
        {
            _table = InitializeTable(DefaultPolynomial);
            _seed = DefaultSeed;
            Initialize();
        }

        public Crc32(uint polynomial, uint seed)
        {
            _table = InitializeTable(polynomial);
            this._seed = seed;
            Initialize();
        }

        public override int HashSize => 32;

        public override void Initialize()
        {
            _hash = _seed;
        }

        protected override void HashCore(byte[] buffer, int start, int length)
        {
            _hash = CalculateHash(_table, _hash, buffer, start, length);
        }

        protected override byte[] HashFinal()
        {
            var hashBuffer = UInt32ToBigEndianBytes(~_hash);
            HashValue = hashBuffer;
            return hashBuffer;
        }

        public static uint Compute(byte[] buffer)
        {
            return ~CalculateHash(InitializeTable(DefaultPolynomial), DefaultSeed, buffer, 0, buffer.Length);
        }

        public static uint Compute(uint seed, byte[] buffer)
        {
            return ~CalculateHash(InitializeTable(DefaultPolynomial), seed, buffer, 0, buffer.Length);
        }

        public static uint Compute(uint polynomial, uint seed, byte[] buffer)
        {
            return ~CalculateHash(InitializeTable(polynomial), seed, buffer, 0, buffer.Length);
        }

        private static uint[] InitializeTable(uint polynomial)
        {
            if (polynomial == DefaultPolynomial && _defaultTable != null)
                return _defaultTable;

            var createTable = new uint[256];
            for (var i = 0; i < 256; i++)
            {
                var entry = (uint) i;
                for (var j = 0; j < 8; j++)
                    if ((entry & 1) == 1)
                        entry = (entry >> 1) ^ polynomial;
                    else
                        entry = entry >> 1;
                createTable[i] = entry;
            }

            if (polynomial == DefaultPolynomial)
                _defaultTable = createTable;

            return createTable;
        }

        private static uint CalculateHash(uint[] table, uint seed, byte[] buffer, int start, int size)
        {
            var crc = seed;
            for (var i = start; i < size; i++)
                unchecked
                {
                    crc = (crc >> 8) ^ table[buffer[i] ^ (crc & 0xff)];
                }

            return crc;
        }

        private byte[] UInt32ToBigEndianBytes(uint x)
        {
            return new[]
            {
                (byte) ((x >> 24) & 0xff),
                (byte) ((x >> 16) & 0xff),
                (byte) ((x >> 8) & 0xff),
                (byte) (x & 0xff)
            };
        }

        // Added by Tal Aloni 2013.07.11
        public static uint Updc32(byte octet, uint crc)
        {
            var table = InitializeTable(DefaultPolynomial);
            return table[(crc ^ octet) & 0xff] ^ (crc >> 8);
        }
    }
}