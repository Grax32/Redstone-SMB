/* Based on https://stackoverflow.com/a/30123190/3419770
 */

using System;
using System.IO;
using System.Security.Cryptography;
using RedstoneSmb.Utilities.ByteUtils;

namespace RedstoneSmb.Utilities.Cryptography
{
    public static class AesCmac
    {
        public static byte[] CalculateAesCmac(byte[] key, byte[] buffer, int offset, int length)
        {
            var data = ByteReader.ReadBytes(buffer, offset, length);
            return CalculateAesCmac(key, data);
        }

        public static byte[] CalculateAesCmac(byte[] key, byte[] data)
        {
            // SubKey generation
            // step 1, AES-128 with key K is applied to an all-zero input block.
            var l = AesEncrypt(key, new byte[16], new byte[16]);

            // step 2, K1 is derived through the following operation:
            var firstSubkey =
                Rol(l); //If the most significant bit of L is equal to 0, K1 is the left-shift of L by 1 bit.
            if ((l[0] & 0x80) == 0x80)
                firstSubkey[15] ^=
                    0x87; // Otherwise, K1 is the exclusive-OR of const_Rb and the left-shift of L by 1 bit.

            // step 3, K2 is derived through the following operation:
            var secondSubkey =
                Rol(firstSubkey); // If the most significant bit of K1 is equal to 0, K2 is the left-shift of K1 by 1 bit.
            if ((firstSubkey[0] & 0x80) == 0x80)
                secondSubkey[15] ^=
                    0x87; // Otherwise, K2 is the exclusive-OR of const_Rb and the left-shift of K1 by 1 bit.

            // MAC computing
            if ((data.Length != 0 && data.Length % 16 == 0))
            {
                // If the size of the input message block is equal to a positive multiple of the block size (namely, 128 bits),
                // the last block shall be exclusive-OR'ed with K1 before processing
                for (var j = 0; j < firstSubkey.Length; j++)
                    data[data.Length - 16 + j] ^= firstSubkey[j];
            }
            else
            {
                // Otherwise, the last block shall be padded with 10^i
                var padding = new byte[16 - data.Length % 16];
                padding[0] = 0x80;

                data = global::RedstoneSmb.Utilities.ByteUtils.ByteUtils.Concatenate(data, padding);

                // and exclusive-OR'ed with K2
                for (var j = 0; j < secondSubkey.Length; j++)
                    data[data.Length - 16 + j] ^= secondSubkey[j];
            }

            // The result of the previous process will be the input of the last encryption.
            var encResult = AesEncrypt(key, new byte[16], data);

            var hashValue = new byte[16];
            Array.Copy(encResult, encResult.Length - hashValue.Length, hashValue, 0, hashValue.Length);

            return hashValue;
        }

        private static byte[] AesEncrypt(byte[] key, byte[] iv, byte[] data)
        {
            using (var ms = new MemoryStream())
            {
                var aes = new RijndaelManaged();
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.None;

                using (var cs = new CryptoStream(ms, aes.CreateEncryptor(key, iv), CryptoStreamMode.Write))
                {
                    cs.Write(data, 0, data.Length);
                    cs.FlushFinalBlock();

                    return ms.ToArray();
                }
            }
        }

        private static byte[] Rol(byte[] b)
        {
            var r = new byte[b.Length];
            byte carry = 0;

            for (var i = b.Length - 1; i >= 0; i--)
            {
                var u = (ushort) (b[i] << 1);
                r[i] = (byte) ((u & 0xff) + carry);
                carry = (byte) ((u & 0xff00) >> 8);
            }

            return r;
        }
    }
}