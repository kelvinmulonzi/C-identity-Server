using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace AuthorizationServer.Services
{
    public interface ISigningKeyService
    {
        RsaSecurityKey GetSecurityKey();
        JsonWebKey GetPublicJsonWebKey();
        string KeyId { get; }
    }

    public class SigningKeyService : ISigningKeyService
    {
        private readonly RsaSecurityKey _key;
        public string KeyId { get; }

        public SigningKeyService(IWebHostEnvironment env)
        {
            var keyDir = Path.Combine(env.ContentRootPath, "Keys");
            Directory.CreateDirectory(keyDir);
            var keyPath = Path.Combine(keyDir, "signing.key");

            var rsa = RSA.Create(2048);
            if (File.Exists(keyPath))
            {
                rsa.ImportRSAPrivateKey(File.ReadAllBytes(keyPath), out _);
            }
            else
            {
                File.WriteAllBytes(keyPath, rsa.ExportRSAPrivateKey());
            }

            KeyId = ComputeKeyId(rsa);
            _key = new RsaSecurityKey(rsa) { KeyId = KeyId };
        }

        public RsaSecurityKey GetSecurityKey() => _key;

        public JsonWebKey GetPublicJsonWebKey()
        {
            var parameters = ((RSA)_key.Rsa).ExportParameters(false);
            return new JsonWebKey
            {
                Kty = "RSA",
                Use = "sig",
                Alg = SecurityAlgorithms.RsaSha256,
                Kid = KeyId,
                N = Base64UrlEncoder.Encode(parameters.Modulus),
                E = Base64UrlEncoder.Encode(parameters.Exponent)
            };
        }

        private static string ComputeKeyId(RSA rsa)
        {
            var pub = rsa.ExportSubjectPublicKeyInfo();
            var hash = SHA256.HashData(pub);
            return Base64UrlEncoder.Encode(hash)[..16];
        }
    }
}
