using OpenCryptograph;
using System;
using System.Numerics;

string output = Hash.SHA256("Hello World!");
byte[] outArray = Hash.SHA256Bytes("Hello World!");
Console.WriteLine("SHA256: " + output);
Key key = new Key();
Console.WriteLine("Public Key: " + key.publicKey);
Console.WriteLine("Private Key: " + key.privateKey);
BigInteger encrypted = Key.Encrypt("1234567", key.publicKey);
Console.WriteLine("Encrypted: " + encrypted);
Console.WriteLine("Decrypted: " + key.Decrypt(encrypted));