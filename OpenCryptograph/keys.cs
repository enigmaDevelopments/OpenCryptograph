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
        private readonly BigInteger privateKey;
        public readonly BigInteger publicKey;
        public Key()
        {
            privateKey = GetPrime();

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
    }
}
