using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using EosSharp.Core.Helpers;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using EosSharp.Core.Interfaces;
using System.Text;

namespace EosSharp.Core.Providers
{
    public class MultiSignProvider : ISignProvider 
    {
        private readonly Dictionary<string, string> Keys = new Dictionary<string, string>();

        /// <summary>
        /// Create provider with single private key
        /// </summary>
        /// <param name="privateKey"></param>
        public MultiSignProvider(string privateKey)
        {
            Keys.Add(PublicKeyFromPrivateKey(privateKey), privateKey);
        }
        /// <summary>
        /// Get available public keys from signature provider
        /// </summary>
        /// <returns>List of public keys</returns>
        public Task<IEnumerable<string>> GetAvailableKeys()
        {
            return Task.FromResult(Keys.Keys.AsEnumerable());
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
                Hex.HexToBytes(chainId),
                signBytes,
                new byte[32]
            };

            var hash = Sha256Manager2.GetHash(SerializationHelper.Combine(data));

            return Task.FromResult(availableAndReqKeys.Select(key =>
            {
                string keyType = GetKeyType(key);
                var KeyTypeBytes = Encoding.UTF8.GetBytes(keyType);

                var sign = SignWithChainPrivateKey(Keys[key], hash);
                byte[] fullSign;
                if (keyType == "GM") {
                    byte[] pubKeyBytes = CryptoHelper.PubKeyStringToBytes(key);
                    if((pubKeyBytes.Length + sign.Length) > 105)
                    {
                        throw new Exception("GM public key and signature length exceeds 105!");
                    }

                    fullSign = new byte[105];
                    Buffer.BlockCopy(pubKeyBytes, 0, fullSign, 0, pubKeyBytes.Length);
                    Buffer.BlockCopy(sign, 0, fullSign, pubKeyBytes.Length, sign.Length);
                }
                else
                {
                    fullSign = sign;
                }

                var checksum = Ripemd160Manager2.GetHash(SerializationHelper.Combine(new List<byte[]>() { fullSign, KeyTypeBytes })).Take(4).ToArray();
                var signAndChecksum = new List<byte[]>() { fullSign, checksum };

                return "SIG_"+keyType+"_" + Base582.Encode(SerializationHelper.Combine(signAndChecksum));
            }));

        }
        /// <summary>
        /// Create provider with list of private keys
        /// </summary>
        /// <param name="privateKeys"></param>
        public MultiSignProvider(List<string> privateKeys)
        {
            if (privateKeys == null || privateKeys.Count == 0)
                throw new ArgumentNullException("privateKeys");

            foreach (var key in privateKeys)
            {
                Keys.Add(PublicKeyFromPrivateKey(key), key);
            }
        }
        public static string GetKeyType(string key)
        {
            string k3 = key.Substring(3);
            if (key.StartsWith("EOS") || k3.StartsWith("_K1_"))
            {
                return "K1";
            }
            else if (k3.StartsWith("_GM_"))
            {
                return "GM";
            }
            else if (k3.StartsWith("_R1_"))
            {
                return "R1";
            }
            else
            {
                return "K1";
                //throw new Exception("Invalid/unsupported key type!");
            }

        }
        public static string GetKeyTypeInt(string key)
        {
            string k3 = key.Substring(3);
            if (key.StartsWith("EOS") || k3.StartsWith("_K1_"))
            {
                return "K1";
            }
            else if (k3.StartsWith("_GM_"))
            {
                return "GM";
            }
            else if (k3.StartsWith("_R1_"))
            {
                return "R1";
            }
            else
            {
                return "K1";
                //throw new Exception("Invalid/unsupported key type!");
            }

        }
        public static X9ECParameters GetX9ECParamsFromKeyType(string keyType)
        {
            if (keyType == "K1" || keyType == "sha256x2")
            {
                return ECNamedCurveTable.GetByName("secp256k1");
            }
            else if (keyType == "R1")
            {

                return ECNamedCurveTable.GetByName("secp256r1");
            }
            else if (keyType == "GM")
            {

                return ECNamedCurveTable.GetByName("sm2p256v1");
            }
            else
            {
                throw new Exception("Invalid/unsupported key type!");
            }
        }
        public static X9ECParameters GetX9ECParamsFromKey(string key)
        {
            return GetX9ECParamsFromKeyType(GetKeyType(key));
        }
        public static byte[] SignWithChainPrivateKey(string chainPrivateKey, byte[] signPayload)
        {

            if (chainPrivateKey.StartsWith("PVT_GM_"))
                return Sign(ECNamedCurveTable.GetByName("sm2p256v1"), signPayload, CryptoHelper.GetPrivateKeyBytesWithoutCheckSum(chainPrivateKey));
            else if(chainPrivateKey.StartsWith("PVT_R1_"))
                return Sign(ECNamedCurveTable.GetByName("secp256r1"), signPayload, CryptoHelper.GetPrivateKeyBytesWithoutCheckSum(chainPrivateKey));
            else
                return Sign(ECNamedCurveTable.GetByName("secp256k1"), signPayload, CryptoHelper.GetPrivateKeyBytesWithoutCheckSum(chainPrivateKey));
        }
        public static byte[]  PublicKeyBytesFromPrivateKey(string chainPrivateKey)
        {
            //Console.WriteLine("multi d: "+Org.BouncyCastle.Utilities.Encoders.Hex.ToHexString(CryptoHelper.GetPrivateKeyBytesWithoutCheckSum(chainPrivateKey)));

            BigInteger dValue = new BigInteger(1, CryptoHelper.GetPrivateKeyBytesWithoutCheckSum(chainPrivateKey));
            X9ECParameters x9ECParameters = GetX9ECParamsFromKey(chainPrivateKey);



            ECDomainParameters ecParams = new ECDomainParameters(x9ECParameters.Curve, x9ECParameters.G, x9ECParameters.N, x9ECParameters.H);
            ECPrivateKeyParameters privKeyParams = new ECPrivateKeyParameters(dValue, ecParams);

            byte[] pubKeyBytes = (new Org.BouncyCastle.Math.EC.Multiplier.FixedPointCombMultiplier()).Multiply(ecParams.G, (privKeyParams).D).Normalize().GetEncoded(true);
            return pubKeyBytes;
        }

        public static string PublicKeyFromPrivateKey(string chainPrivateKey)
        {
            byte[] pubKeyBytes = PublicKeyBytesFromPrivateKey(chainPrivateKey);
            string keyType = GetKeyType(chainPrivateKey);

            if (keyType == "K1")
            {
                return CryptoHelper.PubKeyBytesToString(pubKeyBytes);
            }
            else
            {
                return CryptoHelper.PubKeyBytesToString(pubKeyBytes, keyType, "PUB_" + keyType + "_");
            }

        }

        public static byte[] Sign(X9ECParameters x9ECParameters, byte[] signPayload, byte[] dBytes, byte[] prependPublicKey = null)
        {
            DeterministicECDSA signer = new DeterministicECDSA();
            BigInteger dValue = new BigInteger(1, dBytes);

            ECDomainParameters ecParams = new ECDomainParameters(x9ECParameters.Curve, x9ECParameters.G, x9ECParameters.N, x9ECParameters.H);
            ECPrivateKeyParameters privKeyParams = new ECPrivateKeyParameters(dValue, ecParams);

            signer.Init(true, privKeyParams);
            BigInteger[] rs = signer.GenerateSignature(signPayload);
            if (rs[1].CompareTo(x9ECParameters.N.ShiftRight(1)) > 0)
            {
                rs[1] = x9ECParameters.N.Subtract(rs[1]);
            }

            

            byte[] bs;
                
            //Console.WriteLine("MultiSignProvider:\nr: "+Org.BouncyCastle.Utilities.Encoders.Hex.ToHexString(rs[0].ToByteArrayUnsigned())+"\ns: "+Org.BouncyCastle.Utilities.Encoders.Hex.ToHexString(rs[1].ToByteArrayUnsigned()));

            using (MemoryStream ms = new MemoryStream())
            {
                if(prependPublicKey != null)
                {
                    ms.Write(prependPublicKey, 0, prependPublicKey.Length);
                }
                byte[] enc = PlainDsaEncoding.Instance.Encode(x9ECParameters.N, rs[0], rs[1]);
                ms.WriteByte((byte)0x20);
                ms.Write(enc,0,enc.Length);
                bs = ms.ToArray();
            
                
                //Console.WriteLine("MultiSignProvider bs: "+Org.BouncyCastle.Utilities.Encoders.Hex.ToHexString(bs));

                return bs;
            }
        }
        public static bool Verify(X9ECParameters x9ECParameters, byte[] signPayload, byte[] publicKeyBytes, BigInteger r, BigInteger s)
        {

            ECDsaSigner signer = new ECDsaSigner();

            ECDomainParameters ecParams = new ECDomainParameters(x9ECParameters.Curve, x9ECParameters.G, x9ECParameters.N, x9ECParameters.H);
            ECPublicKeyParameters pubKeyParams = new ECPublicKeyParameters(ecParams
                .Curve.DecodePoint(publicKeyBytes), ecParams);
            signer.Init(false, pubKeyParams);
            return signer.VerifySignature(signPayload, r, s);
        }

    }
}

