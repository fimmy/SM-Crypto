// See https://aka.ms/new-console-template for more information
using SM_Crypto;




var cip = "04eff4bbe5264e48c7add88e1a7eb55508427337bf66291dd1bd2001ad978ef83377006746767314c240528b0aeb1782c6973347ebf6b16feeef108b2112092c45bf9baf355656243fae4c469e743b1bed07ff35770dfabd5f2b87b79e5eee20df490453fab10f184944ed4d";
var resb = SM2.Decrypt(cip.HexStringToBytes(), "144cfecfac60daa934beb73c915e6b090ce90a9efd7b50923311fae1447468ca".HexStringToBytes());
Console.WriteLine(resb.ToUTF8String());







var text = "Hello World";
var input = text.UTF8StringToBytes();
var key = "0123456789ABCDEF";
var keyBytes = key.UTF8StringToBytes();
var iv = "0123456789ABCDEF";
var ivBytes = iv.UTF8StringToBytes();

#region SM2加解密
var keyPair=SM2.GenerateSm2Key();
var pubKey = keyPair.publicKey;
var priKey = keyPair.privateKey;
Console.WriteLine($"src:{text}");
Console.WriteLine("mode:SM2");

Console.WriteLine($"public key hex:{pubKey.ToHexString()}");
Console.WriteLine($"private key hex:{priKey.ToHexString()}");

Console.WriteLine($"public key base64:{pubKey.ToBase64String()}");
Console.WriteLine($"private key base64:{priKey.ToBase64String()}");
var SM2EncResult=SM2.Encrypt(input, pubKey);
Console.WriteLine($"enc hex:{SM2EncResult.ToHexString()}");
Console.WriteLine($"enc base64:{SM2EncResult.ToBase64String()}");


Console.WriteLine();
#endregion

#region SM3加密
Console.WriteLine($"src:{text}");
Console.WriteLine($"key:{key}");
var SM3Result=SM3.Encrypt(input);
Console.WriteLine("mode:SM3");
Console.WriteLine($"hex:{SM3Result.ToHexString()}");
Console.WriteLine($"base64:{SM3Result.ToBase64String()}");
Console.WriteLine();

var SM3HMACResult = SM3.Encrypt(input, keyBytes);
Console.WriteLine("mode:SM3-HMAC");
Console.WriteLine($"hex:{SM3HMACResult.ToHexString()}");
Console.WriteLine($"base64:{SM3HMACResult.ToBase64String()}");
Console.WriteLine();
#endregion

#region SM4 加解密

Console.WriteLine($"src:{text}");
Console.WriteLine($"key:{key}");
Console.WriteLine($"iv:{iv}");
Console.WriteLine();
Console.WriteLine($"mode:SM4-CBC");
var CBCResult=SM4.EncryptCBC(input, keyBytes, ivBytes);
Console.WriteLine($"hex:{CBCResult.ToHexString()}");
Console.WriteLine($"base64:{CBCResult.ToBase64String()}");
Console.WriteLine();
Console.WriteLine($"mode:SM4-CBC");
Console.WriteLine($"iv:{iv}");
var EBCResult = SM4.EncryptECB(input, keyBytes);
Console.WriteLine($"hex:{EBCResult.ToHexString()}");
Console.WriteLine($"base64:{EBCResult.ToBase64String()}");
Console.WriteLine();

#endregion SM4 加解密

