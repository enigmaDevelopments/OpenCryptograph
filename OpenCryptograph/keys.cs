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
        public Key()
        {
            privateKey1 = GetPrime();
            privateKey2 = GetPrime();
            publicKey = privateKey1 * privateKey2;
        }

        private BigInteger GetPrime()
        {
            byte[] bytes = new byte[256];
            Random random = new Random(Environment.TickCount);
            BigInteger output;
            random.NextBytes(bytes);
            bytes[31] |= 0x40;
            bytes[31] &= 0x7F;
            bytes[0] |= 0x01;
            output = new BigInteger(bytes);
            return output;

        }

        public BigInteger FastModularExponentiation(BigInteger bas, BigInteger exponent, BigInteger modulo)
        {
            BigInteger output = 1;
            BigInteger power = bas % modulo;
            while (exponent > 0)
            {
                if ((exponent & 1) == 1)
                    output = (output * power) % modulo;
                exponent >>= 1;
                power = (power * power) % modulo;
            }
            return output;
        }
    }
}
// Source is the class in currently taking - CSC-404 Foundations of Computation