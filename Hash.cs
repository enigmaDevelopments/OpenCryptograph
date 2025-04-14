namespace OpenCryptograph
{

    public static class Hash
    {
        public static byte[] Shake128(byte[] input, int outputByteLen)
        {
            return Keccak(168, input, 0x1F, outputByteLen);
        }
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
            #region make lanes
            ulong[][] lanes = (from i in Enumerable.Range(0, 5) select new ulong[5]).ToArray();
            for (int i = 0; i < 5; i++)
                for (int j = 0; j < 5; j++)
                    lanes[i][j] = Load64(state.Skip((j*5 + i) * 8).Take(8).ToArray());
            #endregion
            byte R = 1;
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
                for (int i = 0; i < 5; i++)
                {
                    ulong[] temp = new ulong[5];
                    for (int j = 0; j < 5; j++)
                        temp[j] = lanes[j][i];
                    for (int j = 0; j < 5; j++)
                        lanes[j][i] = temp[j] ^ ((~temp[(j + 1) % 5]) & temp[(j + 2) % 5]);
                }
                #endregion
                #region ι
                for (int i = 0; i < 7; i++)
                {
                    R = (byte)((R << 1) ^ ((R >> 7) * 0x71));
                    if ((R & 2) == 2)
                        lanes[0][0] ^= (ulong)1 << ((1 << i)-1);
                }
                #endregion
            }
            #region set state
            for (int i = 0; i < 5; i++)
                for (int j = 0; j < 5; j++)
                    Store64(lanes[i][j]).CopyTo(state, (j * 5 + i) * 8);
            #endregion
        }
        private static byte[] Keccak(int rate, byte[] input, byte delimitedSuffix, int outputLength)
        {
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
                    KeccakF1600(ref state);
                    blockSize = 0;
                }
            }
            #endregion
            #region padding
            state[blockSize] ^= delimitedSuffix;
            if (((delimitedSuffix & 0x80) != 0) && (blockSize == (rate - 1)))
                KeccakF1600(ref state);
            state[rate - 1] ^= 0x80;
            KeccakF1600(ref state);
            #endregion
            #region squeeze
            for (int i = 0; i < outputLength; i += blockSize)
            {
                KeccakF1600(ref state);
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
