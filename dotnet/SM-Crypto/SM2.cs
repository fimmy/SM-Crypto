using Org.BouncyCastle.Asn1.GM;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Crypto.Signers;

namespace SM_Crypto
{
    public static class SM2
    {
        /// <summary>
        /// 生成SM2公钥私钥
        /// </summary>
        /// <returns></returns>
        public static (byte[] publicKey, byte[] privateKey) GenerateSm2Key()
        {
            byte[] pubKey;
            byte[] priKey;
            var ecKeyPairGenerator = new ECKeyPairGenerator();
            ecKeyPairGenerator.Init(new ECKeyGenerationParameters(new ECDomainParameters(GMNamedCurves.GetByName("SM2P256V1")), new SecureRandom()));
            var keyPair = ecKeyPairGenerator.GenerateKeyPair();
            pubKey = ((ECPublicKeyParameters)keyPair.Public).Q.GetEncoded(false);
            priKey = ((ECPrivateKeyParameters)keyPair.Private).D.ToByteArray();
            return (pubKey, priKey);
        }
        /// <summary>
        /// SM2加密
        /// </summary>
        /// <param name="input">输入</param>
        /// <param name="publicKey">公钥</param>
        /// <returns></returns>
        public static byte[] Encrypt(byte[] input, byte[] publicKey, SM2Engine.Mode mode = SM2Engine.Mode.C1C3C2)
        {
            var x9ec = GMNamedCurves.GetByName("SM2P256V1");
            ICipherParameters publicKeyParameters = new ECPublicKeyParameters(x9ec.Curve.DecodePoint(publicKey), new ECDomainParameters(x9ec));

            var sm2 = new SM2Engine(new SM3Digest(), mode);
            sm2.Init(true, new ParametersWithRandom(publicKeyParameters));
            byte[] result = sm2.ProcessBlock(input, 0, input.Length);
            return result;
        }
        /// <summary>
        /// SM2解密
        /// </summary>
        /// <param name="input">输入</param>
        /// <param name="privateKey">私钥</param>
        /// <returns></returns>
        public static byte[] Decrypt(byte[] input, byte[] privateKey, SM2Engine.Mode mode = SM2Engine.Mode.C1C3C2)
        {
            var privateKeyParameters = new ECPrivateKeyParameters(new BigInteger(1, privateKey), new ECDomainParameters(GMNamedCurves.GetByName("SM2P256V1")));

            var sm2 = new SM2Engine(new SM3Digest(), mode);
            sm2.Init(false, privateKeyParameters);
            byte[] result = sm2.ProcessBlock(input, 0, input.Length);
            return result;
        }
        /// <summary>
        /// 签名
        /// </summary>
        /// <param name="input">输入</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="userId">用户标识</param>
        /// <returns></returns>
        public static byte[] Sign(byte[] input, byte[] privateKey, byte[] userId = null, SM2Engine.Mode mode = SM2Engine.Mode.C1C3C2)
        {
            var privateKeyParameters = new ECPrivateKeyParameters(new BigInteger(1, privateKey), new ECDomainParameters(GMNamedCurves.GetByName("SM2P256V1")));
            var sm2 = new SM2Signer(new SM3Digest());
            ICipherParameters cp;
            if (userId != null)
            {
                cp = new ParametersWithID(new ParametersWithRandom(privateKeyParameters), userId);
            }
            else
            {
                cp = new ParametersWithRandom(privateKeyParameters);
            }
            sm2.Init(true, cp);
            sm2.BlockUpdate(input, 0, input.Length);
            return sm2.GenerateSignature();
        }
    }
}
