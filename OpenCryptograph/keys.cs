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
        //d
        private readonly BigInteger privateKey;
        //n
        public readonly BigInteger publicKey;
        //e
        public const int constantKey = 65537;
        private readonly Random random;
        public Key()
        {
            random = new Random();
            BigInteger p = GetPrime();
            BigInteger q = GetPrime();
            publicKey = p*q;
            privateKey = ExtendedGCF((p - 1) * (q - 1), constantKey);
        }

        private BigInteger GetPrime()
        {
            byte[] bytes = new byte[256];
            BigInteger output;
            do
            {
                Random random = new Random();
                random.NextBytes(bytes);
                bytes[0] |= 0x07;
                output = new BigInteger(bytes);
                output = BigInteger.Abs(output);
                output = BigInteger.RotateRight(output, 1);
            }while (MillerRabinPrime(output,100) || output - 1 % constantKey == 0);
            return output;
        }

        private bool MillerRabinPrime(BigInteger input, int certanty)
        {
            BigInteger exp = input >> 1;
            for (int i = 0; i < certanty; i++)
            {
                byte[] bytes = new byte[255];
                random.NextBytes(bytes);
                BigInteger num = BigInteger.ModPow(BigInteger.Abs(new BigInteger(bytes)) + 2, exp, input);
                if (num == 1 || num == input-1)
                    return true;
            }
            return false;
        }
        public BigInteger ExtendedGCF(BigInteger a, BigInteger b)
        {
            var (output,_) = ExtendedEuclidean(a, b);
            return output + b;
        }

        private (BigInteger, BigInteger) ExtendedEuclidean(BigInteger a, BigInteger b)
        {
            if (b == 0)
                return (1, 0);
            var (x1, y1) = ExtendedEuclidean(b, a % b);
            BigInteger x = y1;
            BigInteger y = x1 - y1 * (a / b);
            return (x, y);
        }
    }
}
// Source is the class in currently taking - CSC-404 Foundations of Computation
// Miller-Rabin sources:
// https://www.youtube.com/watch?v=zmhUlVck3J0
// https://www.youtube.com/watch?v=-BWTS_1Nxao