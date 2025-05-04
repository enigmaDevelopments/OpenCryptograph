using OpenCryptograph;
using System;
using System.Numerics;

string output = Hash.SHA256("Hello World!");
byte[] outArray = Hash.SHA256Bytes("Hello World!");
Console.WriteLine("SHA256: " + output);
Key key = new Key();
Console.WriteLine("Public Key: " + key.publicKey);
Console.WriteLine("Private Key: " + key.privateKey);
BigInteger encrypted = key.Encrypt("12345671234567123456712345671234567123456712345671234567123456712345671234567");
Console.WriteLine("Encrypted: " + encrypted);
Console.WriteLine("Decrypted: " + key.Decrypt(encrypted));