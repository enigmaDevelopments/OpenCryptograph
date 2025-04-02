using System.Diagnostics;

namespace OpenCryptograph
{
    public static class Hash
    {
       private static byte[] Keccak(int rate,int capacity, byte[] inputBytes, byte delimitedSuffix, int outputByteLen)
        {
            Debug.Assert(((rate + capacity) != 1600) || ((rate % 8) != 0));
            List<byte> output = new List<byte>();
            byte[] state = new byte[200];
            int blockSize = 0;
            int inputOffset = 0;
        }
    }
}
// SHA3 infomation sorces:
// https://keccak.team/keccak_specs_summary.html
// https://github.com/XKCP/XKCP/blob/master/Standalone/CompactFIPS202/Python/CompactFIPS202.py
// https://github.com/XKCP/XKCP/blob/master/Standalone/CompactFIPS202/C/Keccak-readable-and-compact.c
// https://en.wikipedia.org/wiki/SHA-3
