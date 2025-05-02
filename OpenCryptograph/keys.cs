using System;
using System.Numerics;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OpenCryptograph
{
    public class Key
    {
        //p
        private readonly BigInteger privateKey1;
        //q
        private readonly BigInteger privateKey2;
        //n
        public readonly BigInteger publicKey;
        //e
        public readonly BigInteger publicKey2;
        private readonly Random random;
        public Key()
        {
            random = new Random();
            privateKey1 = GetPrime();
            privateKey2 = GetPrime();
            publicKey = privateKey1 * privateKey2;
        }

        private BigInteger GetPrime()
        {
            byte[] bytes = new byte[256];
            BigInteger output;
            random.NextBytes(bytes);
            bytes[255] |= 0x40;
            bytes[255] &= 0x7F;
            bytes[0] |= 0x03;
            output = new BigInteger(bytes);
            return output;

        }
        public bool MillerRabinPrime(BigInteger input, int certanty)
        {
            BigInteger exp = input >> 1;
            for (int i = 0; i < certanty; i++)
            {
                byte[] bytes = new byte[255];
                random.NextBytes(bytes);
                BigInteger num = BigInteger.ModPow(BigInteger.Abs(new BigInteger(bytes)) + 2, exp, input);
                if (num == 1 || num == input-1)
                    return false;
            }
            return true;
        }
    }
}
// Source is the class in currently taking - CSC-404 Foundations of Computation
// Miller-Rabin sources:
// https://www.youtube.com/watch?v=zmhUlVck3J0
// https://www.youtube.com/watch?v=-BWTS_1Nxao