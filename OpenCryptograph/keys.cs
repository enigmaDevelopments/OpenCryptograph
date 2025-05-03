using System;
using System.Numerics;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace OpenCryptograph
{
    public class Key
    {
        //d
        public readonly BigInteger privateKey;
        //n
        public readonly BigInteger publicKey;
        //e
        public const int constantKey = 3;
        private readonly Random random;
        public Key()
        {
            //random = new Random();
            //BigInteger p = GetPrime();
            //BigInteger q = GetPrime();
            BigInteger p = 11;
            BigInteger q = 17;
            publicKey = p * q;


            privateKey = ExtendedGCF(constantKey,(p - 1) * (q - 1));
        }
        public static BigInteger Encrypt(string input, BigInteger publicKey)
        {
            byte[] bytes = Encoding.GetEncoding("UTF-8").GetBytes(input);
            List<byte> output = new List<byte>();
            int blockSize = publicKey.GetByteCount();
            input = input.PadLeft(bytes.Length + (blockSize - bytes.Length % blockSize) % blockSize, '\0');
            bytes = Encoding.GetEncoding("UTF-8").GetBytes(input);
            Console.WriteLine("Bytes: " + Encoding.ASCII.GetString(bytes));
            for (int i = 0; i < bytes.Length; i += blockSize)
            {
                BigInteger m = new BigInteger(bytes.Skip(i).Take(blockSize).ToArray());
                Console.WriteLine("Block: " + Encoding.ASCII.GetString(bytes.Skip(i).Take(blockSize).ToArray()));
                Console.WriteLine(string.Join("", bytes.Skip(i).Take(blockSize).ToArray().Select(b => b.ToString("x2"))));
                m = BigInteger.ModPow(m, constantKey, publicKey);
                output.AddRange(m.ToByteArray());
            }
            return new BigInteger(output.ToArray());
        }
        public string Decrypt(BigInteger input)
        {
            List<byte> output = new List<byte>();
            int blockSize = publicKey.GetByteCount();
            byte[] bytes = input.ToByteArray();
            for (int i = 0; i < bytes.Length; i += blockSize)
            {
                Console.WriteLine(i);
                BigInteger m = new BigInteger(bytes.Skip(i).Take(blockSize).ToArray());
                m = BigInteger.ModPow(m, privateKey, publicKey);
                output.AddRange(m.ToByteArray());
            }
            return Encoding.ASCII.GetString(output.ToArray());
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
            } while (MillerRabinPrime(output, 100) || output - 1 % constantKey == 0);
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
                if (num == 1 || num == input - 1)
                    return true;
            }
            return false;
        }
        public BigInteger ExtendedGCF(BigInteger a, BigInteger b)
        {
            var (output, _) = ExtendedEuclidean(a, b);
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