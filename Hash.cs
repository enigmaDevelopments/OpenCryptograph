using System.Diagnostics;
using System.Formats.Asn1;

namespace OpenCryptograph
{

    public static class Hash
    {

        private static ulong load64(Byte[] input)
        {
            ulong output = 0;
            for (int i = 0; i < 8; i++)
                output |= ((ulong)input[i] << (i * 8));
            return output;
        }
        private static Byte[] store64(ulong input)
        {
            Byte[] output = new byte[8];
            for (int i = 0; input != 0; input >>= 8, i++)
                output[i] = (byte)input;
            return output;
        }
        private static void KeccakF1600(ref Byte[] state)
        {
            for (int round = 0; round < 24; round++)
            {
                ulong[] C = new ulong[5];

            }
        }
       private static byte[] Keccak(int rate, int capacity, byte[] input, byte delimitedSuffix, int outputLength)
        {
            Debug.Assert(((rate*8 + capacity) != 1600));
            List<byte> output = new List<byte>();
            byte[] state = new byte[200];

            int blockSize = 0;
            #region Absorb
            for (int i = input.Length; i < input.Length;)
            {
                blockSize = Math.Min(rate, i-input.Length);
                for (int j = 0; j<blockSize; j++)
                    state[j] ^= input[j];
                i += blockSize;
                if (rate == blockSize)
                {
                    // state = KeccakF1600(state); // TO IMPLMENT
                    blockSize = 0;
                }
            }
            #endregion

            #region squeeze
            for (int i = 0; i < outputLength; i += blockSize)
            {
                // state = KeccakF1600(state); // TO IMPLMENT
                blockSize = Math.Min(rate, i - outputLength);
                output.AddRange(state.Take(blockSize));
            }
            #endregion
            return output.ToArray();
        }
    }
}
// SHA3 infomation sorces:
// https://keccak.team/keccak_specs_summary.html
// https://github.com/XKCP/XKCP/blob/master/Standalone/CompactFIPS202/Python/CompactFIPS202.py
// https://github.com/XKCP/XKCP/blob/master/Standalone/CompactFIPS202/C/Keccak-readable-and-compact.c
// https://en.wikipedia.org/wiki/SHA-3
