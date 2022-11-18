using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SM_Crypto
{
    public static class SM4
    {
        /// <summary>
        /// CBC模式加密，PKCS7Padding填充
        /// </summary>
        /// <param name="input">明文byte[]</param>
        /// <param name="key">密钥,必须为16位byte（128bit）</param>
        /// <param name="iv">偏移量,必须为16位byte（128bit）</param>
        /// <returns>密文byte[]</returns>
        public static byte[] EncryptCBC(byte[] input, byte[] key, byte[] iv)
        {
            // 加密
            KeyParameter keyParameter = ParameterUtilities.CreateKeyParameter("SM4", key);
            ParametersWithIV keyParamWithIv = new ParametersWithIV(keyParameter, iv);

            IBufferedCipher inCipher = CipherUtilities.GetCipher("SM4/CBC/PKCS7Padding");
            inCipher.Init(true, keyParamWithIv);
            byte[] output = inCipher.DoFinal(input);
            return output;
        }
        /// <summary>
        /// CBC模式解密，PKCS7Padding填充
        /// </summary>
        /// <param name="input">明文byte[]</param>
        /// <param name="key">密钥,必须为16位的byte[]（128bit）</param>
        /// <param name="iv">偏移量,必须为16位的byte[]（128bit）</param>
        /// <returns>密文byte[]</returns>
        public static byte[] DecryptCBC(byte[] input, byte[] key, byte[] iv)
        {            
            // 加密
            KeyParameter keyParameter = ParameterUtilities.CreateKeyParameter("SM4", key);
            ParametersWithIV keyParamWithIv = new ParametersWithIV(keyParameter, iv);

            IBufferedCipher inCipher = CipherUtilities.GetCipher("SM4/CBC/PKCS7Padding");
            inCipher.Init(false, keyParamWithIv);
            byte[] output = inCipher.DoFinal(input);
            return output;

        }
        /// <summary>
        /// EBC模式加密，PKCS7Padding填充
        /// </summary>
        /// <param name="input">明文byte[]</param>
        /// <param name="key">密钥,必须为16位byte（128bit）</param>
        /// <returns>密文byte[]</returns>
        public static byte[] EncryptECB(byte[] input, byte[] key)
        {
            // 加密
            KeyParameter keyParameter = ParameterUtilities.CreateKeyParameter("SM4", key);
            IBufferedCipher inCipher = CipherUtilities.GetCipher("SM4/ECB/PKCS7Padding");
            inCipher.Init(true, keyParameter);
            byte[] output = inCipher.DoFinal(input);
            return output;
        }
        /// <summary>
        /// EBC模式解密，PKCS7Padding填充
        /// </summary>
        /// <param name="input">明文byte[]</param>
        /// <param name="key">密钥,必须为16位的byte[]（128bit）</param>
        /// <returns>密文byte[]</returns>
        public static byte[] DecryptECB(byte[] input, byte[] key)
        {
            // 加密
            KeyParameter keyParameter = ParameterUtilities.CreateKeyParameter("SM4", key);

            IBufferedCipher inCipher = CipherUtilities.GetCipher("SM4/CBC/PKCS7Padding");
            inCipher.Init(false, keyParameter);
            byte[] output = inCipher.DoFinal(input);
            return output;

        }
    }
}
