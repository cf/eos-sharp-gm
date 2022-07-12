using System;
using System.Security.Cryptography;

namespace EosSharp.Core.Helpers
{
    public class Sha256Manager2
    {
        public static byte[] GetHash(byte[] data)
        {
            using (SHA256 mySHA256 = SHA256.Create())
            {
                return mySHA256.ComputeHash(data);
            }
        }
    }
}

