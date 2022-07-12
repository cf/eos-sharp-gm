
using EosSharp.Core.Helpers;
using EosSharp.Core.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EosSharp.Core.Providers
{
    /// <summary>
    /// Signature provider default implementation that stores private keys in memory
    /// </summary>
    public class GMSignProvider 
    {
        /*
        private readonly byte[] KeyTypeBytes = Encoding.UTF8.GetBytes("GM");
        private readonly Dictionary<string, byte[]> Keys = new Dictionary<string, byte[]>();

        /// <summary>
        /// Create provider with single private key
        /// </summary>
        /// <param name="privateKey"></param>
        public GMSignProvider(string privateKey)
        {
        }

        /// <summary>
        /// Create provider with list of private keys
        /// </summary>
        /// <param name="privateKeys"></param>
        public GMSignProvider(List<string> privateKeys)
        {
            if (privateKeys == null || privateKeys.Count == 0)
                throw new ArgumentNullException("privateKeys");

            foreach (var key in privateKeys)
            {
                var privKeyBytes = CryptoHelper.GetPrivateKeyBytesWithoutCheckSum(key);
                var pubKey = CryptoHelper.PubKeyBytesToString(Secp256K1Manager.GetPublicKey(privKeyBytes, true));
                Keys.Add(pubKey, privKeyBytes);
            }
        }

        /// <summary>
        /// Create provider with dictionary of encoded key pairs
        /// </summary>
        /// <param name="encodedKeys"></param>
        public GMSignProvider(Dictionary<string, string> encodedKeys)
        {
            if (encodedKeys == null || encodedKeys.Count == 0)
                throw new ArgumentNullException("encodedKeys");

            foreach (var keyPair in encodedKeys)
            {
                var privKeyBytes = CryptoHelper.GetPrivateKeyBytesWithoutCheckSum(keyPair.Value);
                Keys.Add(keyPair.Key, privKeyBytes);
            }
        }

        /// <summary>
        /// Create provider with dictionary of  key pair with private key as byte array
        /// </summary>
        /// <param name="keys"></param>
        public GMSignProvider(Dictionary<string, byte[]> keys)
        {
            if (keys == null || keys.Count == 0)
                throw new ArgumentNullException("encodedKeys");

            Keys = keys;
        }

        /// <summary>
        /// Get available public keys from signature provider
        /// </summary>
        /// <returns>List of public keys</returns>
        public Task<IEnumerable<string>> GetAvailableKeys()
        {
            return Task.FromResult(Keys.Keys.AsEnumerable());
        }
        private static byte[] StringToByteArray(String hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

        /// <summary>
        /// Sign bytes using the signature provider
        /// </summary>
        /// <param name="chainId">EOSIO Chain id</param>
        /// <param name="requiredKeys">required public keys for signing this bytes</param>
        /// <param name="signBytes">signature bytes</param>
        /// <param name="abiNames">abi contract names to get abi information from</param>
        /// <returns>List of signatures per required keys</returns>
        public Task<IEnumerable<string>> Sign(string chainId, IEnumerable<string> requiredKeys, byte[] signBytes, IEnumerable<string> abiNames = null)
        {
            if (requiredKeys == null)
                return Task.FromResult(new List<string>().AsEnumerable());

            var availableAndReqKeys = requiredKeys.Intersect(Keys.Keys);

            var data = new List<byte[]>()
            {
                StringToByteArray(chainId),
                signBytes,
                new byte[32]
            };

            var hash = Sha256Manager.GetHash(SerializationHelper.Combine(data));

            return Task.FromResult(availableAndReqKeys.Select(key =>
            {
                var sign = Secp256K1Manager.SignCompressedCompact(hash, Keys[key]);
                var check = new List<byte[]>() { sign, KeyTypeBytes };
                var checksum = Ripemd160Manager.GetHash(SerializationHelper.Combine(check)).Take(4).ToArray();
                var signAndChecksum = new List<byte[]>() { sign, checksum };

                return "SIG_K1_" + Base58.Encode(SerializationHelper.Combine(signAndChecksum));
            }));
        }*/
    }
}