using System.Numerics;
using System.Text;

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
        private BigInteger seed;
        public readonly int primeBytes;
        public Key(int primeBytes = 256) : this(Environment.TickCount, primeBytes) { }
        public Key(int seed, int primeBytes = 256) : this(new BigInteger(seed),primeBytes){}
        public Key(string seed,  int primeBytes = 256) : this(new BigInteger(Encoding.UTF8.GetBytes(seed)), 256) { }
        public Key(BigInteger seed, int primeBytes = 256)
        {
            this.primeBytes = primeBytes;
            this.seed = seed;
            BigInteger p = GetPrime();
            BigInteger q = GetPrime();
            publicKey = p * q;
            privateKey = ExtendedGCF(constantKey, (p - 1) * (q - 1));
        }
        public BigInteger Encrypt(string input)
        {
            return Encrypt(input, publicKey);
        }
        public static BigInteger Encrypt(string input, BigInteger publicKey)
        {
            BigInteger output = 0;
            BigInteger blockSize = BigInteger.Pow(256,publicKey.GetByteCount()-1);
            BigInteger parsedInput = new BigInteger(Encoding.UTF8.GetBytes(input));
            while (0 < parsedInput)
            {

                BigInteger m = parsedInput % blockSize;
                parsedInput /= blockSize;
                m = BigInteger.ModPow(m, constantKey, publicKey);
                output *= BigInteger.Pow(256, publicKey.GetByteCount());
                output += m;
            }
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
                output *= blockSize;
                output += m%blockSize;
            }
            return Encoding.ASCII.GetString(output.ToByteArray());
        }

        private BigInteger GetPrime()
        {
            BigInteger output;
            do
            {
                output = Random(primeBytes);
                output = BigInteger.Abs(output);
                output |= (BigInteger.One << (output.GetByteCount() * 8 - 1)) | 0x03;
                if ((output - 1) % constantKey == 0) 
                    continue;
            } while (!MillerRabinPrime(output, 5));
            return output;
        }

        private bool MillerRabinPrime(BigInteger input, int certanty)
        {
            BigInteger exp = input >> 1;
            for (int i = 0; i < certanty; i++)
            {
                BigInteger rand = BigInteger.Abs(Random(primeBytes-1)) + 2;
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
        private BigInteger Random(int Size)
        {
            seed = Hash.Shake128(seed, Size);
            return seed;
        }
    }
}
// Source is the class in currently taking - CSC-404 Foundations of Computation
// Miller-Rabin sources:
// https://www.youtube.com/watch?v=zmhUlVck3J0
// https://www.youtube.com/watch?v=-BWTS_1Nxao