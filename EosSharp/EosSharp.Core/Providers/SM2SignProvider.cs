using System;
using System.IO;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.GM;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;

namespace EosSharp.Core.Providers
{
    public class SM2SignProvider
    {

        /// <summary>
        ///  Sign with private key
        /// </summary>
        /// <param name="macdata">String to be signed</param>
        /// <param name="privateKey">Private key</param>
        /// <returns></returns>
        public static byte[] Sign(byte[] signPayload, AsymmetricKeyParameter privateKey)
        {
            Org.BouncyCastle.Crypto.Signers.SM2Signer signer = new Org.BouncyCastle.Crypto.Signers.SM2Signer();
            signer.Init(true, privateKey);
            signer.BlockUpdate(signPayload, 0, signPayload.Length);
            byte[] sign = signer.GenerateSignature();
            Asn1Sequence sequence = Asn1Sequence.GetInstance(sign);
            DerInteger r = (DerInteger)sequence[0];
            DerInteger s = (DerInteger)sequence[1];

            BigInteger[] bigs = new BigInteger[] { r.Value, s.Value };

            byte[] bs;
            using (MemoryStream ms = new MemoryStream())
            {
                DerSequenceGenerator seq = new DerSequenceGenerator(ms);
                seq.AddObject(new DerInteger(bigs[0]));
                seq.AddObject(new DerInteger(bigs[1]));
                seq.Close();
                bs = ms.ToArray();
            }
            return bs;
        }


        /// <summary>
        /// Use the public key to verify the data to be verified
        /// </summary>
        /// <param name="data">Verification character</param>
        /// <param name="signature">Signature string to be verified</param>
        /// <param name="pkInfo">Public key</param>
        /// <returns></returns>
        public static bool VerifyData(byte[] data, byte[] signature, AsymmetricKeyParameter pkInfo)
        {
            Org.BouncyCastle.Crypto.Signers.SM2Signer signer = new Org.BouncyCastle.Crypto.Signers.SM2Signer();

            signer.Init(false, pkInfo);
            signer.BlockUpdate(data, 0, data.Length);
            return signer.VerifySignature(signature);
        }
    }
}

