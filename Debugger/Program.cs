using OpenCryptograph;
using System;
using System.Numerics;

string output = Hash.SHA256("Hello World!");
byte[] outArray = Hash.SHA256Bytes("Hello World!");
Console.WriteLine("SHA256: " + output);
Key key = new Key();
Console.WriteLine("Key: " + key.publicKey);