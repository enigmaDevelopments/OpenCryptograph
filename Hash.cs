using System.Diagnostics;

namespace OpenCryptograph
{

    public static class Hash
    {
        private static ulong RollLeft(ulong value, int shift)
        {
            shift %= 64;
            return (value << shift) | (value >> (64 - shift));
        }
        private static ulong Load64(Byte[] input)
        {
            ulong output = 0;
            for (int i = 0; i < 8; i++)
                output |= ((ulong)input[i] << (i * 8));
            return output;
        }
        private static Byte[] Store64(ulong input)
        {
            Byte[] output = new byte[8];
            for (int i = 0; input != 0; input >>= 8, i++)
                output[i] = (byte)input;
            return output;
        }
        private static void KeccakF1600(ref Byte[] state)
        {
            ulong[][] lanes = (from i in Enumerable.Range(0, 5) select new ulong[5]).ToArray();
            for (int i = 0; i < 5; i++)
                for (int j = 0; j < 5; j++)
                    lanes[i][j] = Load64(state.Skip((j*5 + i) * 8).Take(8).ToArray());
            for (int round = 0; round < 24; round++)
            {
                #region θ
                ulong[] C = (from lane in lanes select lane[0]^lane[1]^lane[2]^lane[3]^lane[4]).ToArray();
                ulong[] D = new ulong[5];
                for (int i = 0; i < 5; i++)
                    D[i] = C[(i + 4) % 5] ^ RollLeft(C[(i + 1) % 5],1);
                for (int i = 0; i < 5; i++)
                    for (int j = 0; j < 5; j++)
                        lanes[i][j] ^= D[i];
                #endregion
                #region ρ and π
                int x = 1, y = 0;
                ulong current = lanes[x][y];
                for (int i = 0; i < 24; i++)
                {
                    {
                        int temp = x;
                        x = y;
                        y = (2 * temp + 3 * y) % 5;
                    }
                    { 
                        ulong temp = lanes[x][y];
                        lanes[x][y] = RollLeft(current, ((i + 1) * (i + 2)) / 2);
                        current = temp;
                    }
                }
                #endregion
                #region χ
                for (int i = 0; i < 5; j++)
                {
                    ulong[] temp = new ulong[5];
                    for (int j = 0; j < 5; j++)
                        temp[j] = lanes[j][i];
                    for (int j = 0; j < 5; j++)
                        lanes[j][i] = temp[j] ^ ((~temp[(j + 1) % 5]) & temp[(j + 2) % 5]);
                }
                #endregion
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
