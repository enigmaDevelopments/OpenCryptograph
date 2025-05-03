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
        //public const int constantKey = 11;
        public const int constantKey = 65537;
        private readonly Random random;
        public Key()
        {
            random = new Random();
            BigInteger p = GetPrime();
            BigInteger q = GetPrime();
            Console.WriteLine("P: " + p);
            Console.WriteLine("Q: " + q);
            //BigInteger p = 911;
            //BigInteger q = 997;
            publicKey = p * q;


            privateKey = ExtendedGCF(constantKey,(p - 1) * (q - 1));
        }
        public static BigInteger Encrypt(string input, BigInteger publicKey)
        {
            BigInteger output = 0;
            BigInteger blockSize = BigInteger.Pow(256,publicKey.GetByteCount()-1);
            BigInteger parsedInput = new BigInteger(Encoding.UTF8.GetBytes(input));
            Console.WriteLine("Parsed: " + parsedInput.ToString("x2"));
            while (0 < parsedInput)
            {

                BigInteger m = parsedInput % blockSize;
                parsedInput /= blockSize;
                Console.WriteLine("Block: " + Encoding.ASCII.GetString(m.ToByteArray()));
                Console.WriteLine("Num: " + m.ToString("x2"));
                m = BigInteger.ModPow(m, constantKey, publicKey);
                Console.WriteLine("Encrypted: " + m.ToString("x2"));
                Console.WriteLine("Length: " + m.ToByteArray().Length);
                output *= BigInteger.Pow(256, publicKey.GetByteCount());
                output += m;
            }
            Console.WriteLine("Encrypted: " + output.ToString("x2"));
            return output;
        }
        public string Decrypt(BigInteger input)
        {
            BigInteger output = 0;
            BigInteger blockSize = BigInteger.Pow(256, publicKey.GetByteCount());

            while (0 < input)
            {
                BigInteger m = input % blockSize;
                input /= blockSize;
                m = BigInteger.ModPow(m, privateKey, publicKey);
                Console.WriteLine("Decrypted: " + m.ToString("x2"));
                output *= blockSize;
                output += m%blockSize;
            }
            return Encoding.ASCII.GetString(output.ToByteArray());
        }

        private BigInteger GetPrime()
        {
            byte[] bytes = new byte[256];
            BigInteger output;
            do
            {
                random.NextBytes(bytes);
                bytes[255] |= 0x80;
                output = new BigInteger(bytes);
                output = BigInteger.Abs(output);
                output |= 0x03;
                Console.WriteLine(output);
                if ((output - 1) % constantKey == 0) 
                    continue;
            } while (!MillerRabinPrime(output, 100));
            Console.WriteLine("------------");
            return output;
        }

        private bool MillerRabinPrime(BigInteger input, int certanty)
        {
            BigInteger exp = input >> 1;
            for (int i = 0; i < certanty; i++)
            {
                byte[] bytes = new byte[255];
                random.NextBytes(bytes);
                BigInteger rand = BigInteger.Abs(new BigInteger(bytes)) + 2;
                BigInteger num = BigInteger.ModPow(rand, exp, input);
                if (num == 1 || num == input - 1)
                    return true;
            }
            return false;
        }
        public BigInteger ExtendedGCF(BigInteger a, BigInteger b)
        {
            var (output, _) = ExtendedEuclidean(a, b);
            return (output + b)%b;
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