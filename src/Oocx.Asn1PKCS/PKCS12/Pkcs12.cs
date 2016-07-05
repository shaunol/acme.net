using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Oocx.Asn1PKCS.PKCS12
{
    public class Pkcs12 : IPkcs12
    {        
        public void CreatePfxFile(string friendlyName, RSAParameters key, string pathToCertificate, string password, string pathToPfx)
        {
            var keyPair = GetRsaKeyPair(key);

            var certBytes = File.ReadAllBytes(pathToCertificate);

            var store = new Pkcs12Store();
            var certificate = new X509CertificateParser().ReadCertificate(certBytes);

            store.SetKeyEntry(
                friendlyName, 
                new AsymmetricKeyEntry(keyPair.Private), 
                new [] { new X509CertificateEntry(certificate) });

            using (var ms = new MemoryStream())
            {
                var random = new SecureRandom();
                store.Save(ms, password.ToCharArray(), random);
                using (var cert = new X509Certificate2(ms.ToArray(), password, X509KeyStorageFlags.Exportable))
                {
                    var pkcs12 = cert.Export(X509ContentType.Pkcs12, password);
                    File.WriteAllBytes(pathToPfx, pkcs12);
                }
            }
        }

        private static AsymmetricCipherKeyPair GetRsaKeyPair(RSAParameters rp)
        {
            var modulus = new BigInteger(1, rp.Modulus);
            var pubExp = new BigInteger(1, rp.Exponent);

            var pubKey = new RsaKeyParameters(
                false,
                modulus,
                pubExp);

            var privKey = new RsaPrivateCrtKeyParameters(
                modulus,
                pubExp,
                new BigInteger(1, rp.D),
                new BigInteger(1, rp.P),
                new BigInteger(1, rp.Q),
                new BigInteger(1, rp.DP),
                new BigInteger(1, rp.DQ),
                new BigInteger(1, rp.InverseQ));

            return new AsymmetricCipherKeyPair(pubKey, privKey);
        }
    }
}