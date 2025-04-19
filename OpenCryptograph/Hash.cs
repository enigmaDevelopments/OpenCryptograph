namespace OpenCryptograph
{

    public static class Hash
    {
        #region interfaces
        public static byte[] Shake128Bytes(byte[] input, int outputByteLen)
        {
            return Keccak(168, input, 0x1F, outputByteLen);
        }
        public static byte[] Shake256Bytes(byte[] input, int outputByteLen)
        {
            return Keccak(136, input, 0x1F, outputByteLen);
        }
        public static byte[] SHA224Bytes(byte[] input)
        {
            return Keccak(144, input, 0x06, 28);
        }
        public static byte[] SHA256Bytes(byte[] input)
        {
            return Keccak(136, input, 0x06, 32);
        }
        public static byte[] SHA384Bytes(byte[] input)
        {
            return Keccak(104, input, 0x06, 48);
        }
        public static byte[] SHA512Bytes(byte[] input)
        {
            return Keccak(72, input, 0x06, 64);
        }
        public static byte[] Shake128Bytes(string input, int outputByteLen)
        {
            return Shake128Bytes(StringToBytes(input), outputByteLen);
        }
        public static byte[] Shake256Bytes(string input, int outputByteLen)
        {
            return Shake256Bytes(StringToBytes(input), outputByteLen);
        }
        public static byte[] SHA224Bytes(string input)
        {
            return SHA224Bytes(StringToBytes(input));
        }
        public static byte[] SHA256Bytes(string input)
        {
            return SHA256Bytes(StringToBytes(input));
        }
        public static byte[] SHA384Bytes(string input)
        {
            return SHA384Bytes(StringToBytes(input));
        }
        public static byte[] SHA512Bytes(string input)
        {
            return SHA512Bytes(StringToBytes(input));
        }
        public static string Shake128(byte[] input, int outputByteLen)
        {
            return ByteToHex(Shake128Bytes(input, outputByteLen));
        }
        public static string Shake256(byte[] input, int outputByteLen)
        {
            return ByteToHex(Shake256Bytes(input, outputByteLen));
        }
        public static string SHA224(byte[] input)
        {
            return ByteToHex(SHA224Bytes(input));
        }
        public static string SHA256(byte[] input)
        {
            return ByteToHex(SHA256Bytes(input));
        }
        public static string SHA384(byte[] input)
        {
            return ByteToHex(SHA384Bytes(input));
        }
        public static string SHA512(byte[] input)
        {
            return ByteToHex(SHA512Bytes(input));
        }
        public static string Shake128(string input, int outputByteLen)
        {
            return ByteToHex(Shake128Bytes(input, outputByteLen));
        }
        public static string Shake256(string input, int outputByteLen)
        {
            return ByteToHex(Shake256Bytes(input, outputByteLen));
        }
        public static string SHA224(string input)
        {
            return ByteToHex(SHA224Bytes(input));
        }
        public static string SHA256(string input)
        {
            return ByteToHex(SHA256Bytes(input));
        }
        public static string SHA384(string input)
        {
            return ByteToHex(SHA384Bytes(input));
        }
        public static string SHA512(string input)
        {
            return ByteToHex(SHA512Bytes(input));
        }
        #endregion
        private static string ByteToHex(byte[] input)
        {
            return string.Join("", input.Select(b => b.ToString("x2")));
        }
        private static byte[] StringToBytes(string input)
        {
            return System.Text.Encoding.UTF8.GetBytes(input);
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
            for (int i = 0; i<input.Length;)
            {
                blockSize = Math.Min(rate, input.Length-i);
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
            #endregion
            #region squeeze
            for (int i = outputLength; 0 < i; i -= blockSize)
            {
                KeccakF1600(ref state);
                blockSize = Math.Min(rate, i);
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
