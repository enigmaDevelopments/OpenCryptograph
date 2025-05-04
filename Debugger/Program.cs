using OpenCryptograph;
using System.Numerics;

string output = Hash.SHA256String("Hello World!");
byte[] outArray = Hash.SHA256Bytes("Hello World!");
Console.WriteLine("SHA256: " + output);
Key key = new Key(BigInteger.Parse("912312312312334365687697845568432342343524443324534523542342341222452354123"));
Console.WriteLine("Public Key: " + key.publicKey);
BigInteger encrypted = key.Encrypt("12345671234567123456712345671234567123456712345671234567123456712345671234567");
Console.WriteLine("Encrypted: " + encrypted);
Console.WriteLine("Decrypted: " + key.Decrypt(encrypted));