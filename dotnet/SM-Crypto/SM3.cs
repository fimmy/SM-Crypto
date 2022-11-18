using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SM_Crypto
{
    public static class SM3
    {
        /// <summary>
        /// SM3加密
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public static byte[] Encrypt(byte[] input)
        {
            SM3Digest sm3 = new SM3Digest();
            byte[] result = new byte[sm3.GetDigestSize()];//SM3算法产生的哈希值大小
            sm3.BlockUpdate(input, 0, input.Length);
            sm3.DoFinal(result, 0);
            return result;
        }
        /// <summary>
        /// SM3-HMAC加密
        /// </summary>
        /// <param name="input"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public static byte[] Encrypt(byte[] input, byte[] key)
        {
            KeyParameter keyParameter = new KeyParameter(key);
            SM3Digest sm3 = new SM3Digest();

            byte[] result = new byte[sm3.GetDigestSize()];//SM3算法产生的哈希值大小

            HMac mac = new HMac(sm3);//带密钥的杂凑算法
            mac.Init(keyParameter);
            mac.BlockUpdate(input, 0, input.Length);

            mac.DoFinal(result, 0);
            return result;
        }
    }
}
