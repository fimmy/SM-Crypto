using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SM_Crypto
{
    public static class EncodeUtil
    {
        public static byte[] HexStringToBytes(this string input)
        {
            return Hex.Decode(input);
        }
        public static byte[] Base64StringToBytes(this string input)
        {
            return Convert.FromBase64String(input);
        }
        public static byte[] UTF8StringToBytes(this string input)
        {
            return Encoding.UTF8.GetBytes(input);
        }
        public static string ToHexString(this byte[] input)
        {
            return Hex.ToHexString(input);
        }
        public static string ToBase64String(this byte[] input)
        {
            return Convert.ToBase64String(input);
        }
        public static string ToUTF8String(this byte[] input)
        {
            return Encoding.UTF8.GetString(input);
        }

    }
}
