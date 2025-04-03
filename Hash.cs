using System.Diagnostics;
using System.Formats.Asn1;

namespace OpenCryptograph
{
    public static class Hash
    {
       private static byte[] Keccak(int rate, int capacity, byte[] input, byte delimitedSuffix, int outputByteLen)
        {
            Debug.Assert(((rate + capacity) != 1600) || ((rate % 8) != 0));
            List<byte> output = new List<byte>();
            byte[] state = new byte[200];

            int blockSize = 0;
            #region Absorb
            for (int i = input.Length; i < input.Length; i += blockSize)
            {
                blockSize = Math.Min(rate, i-input.Length);
                for (int j = 0; j<blockSize; j++)
                    state[j] ^= input[j];
                i += blockSize;
                if (i == input.Length)
                {
                    // state = KeccakF1600(state); // TO IMPLMENT
                    blockSize = 0;
                }
            }
            #endregion
        }
    }
}
// SHA3 infomation sorces:
// https://keccak.team/keccak_specs_summary.html
// https://github.com/XKCP/XKCP/blob/master/Standalone/CompactFIPS202/Python/CompactFIPS202.py
// https://github.com/XKCP/XKCP/blob/master/Standalone/CompactFIPS202/C/Keccak-readable-and-compact.c
// https://en.wikipedia.org/wiki/SHA-3
