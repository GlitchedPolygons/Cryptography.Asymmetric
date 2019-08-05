using System;
using System.Threading.Tasks;

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;

using Microsoft.Extensions.Logging;

namespace GlitchedPolygons.Services.Cryptography.Asymmetric
{
    /// <summary>
    /// Asymmetric RSA key generator.
    /// </summary>
    public class AsymmetricKeygenRSA : IAsymmetricKeygenRSA
    {
        /// <summary>
        /// Optional error logger.
        /// </summary>
        private readonly ILogger logger;
        
        /// <summary>
        /// Creates a new asymmetric RSA key generator.
        /// </summary>
        public AsymmetricKeygenRSA(ILogger logger = null)
        {
            this.logger = logger;
        }
        
        /// <summary>
        /// Generates an RSA key pair using the specified key size parameter "<paramref name="rsaKeySize"/>".<para> </para>
        /// Returns the RSA key pair <see cref="Tuple"/>, where the first item is the public key and the second is the private key.<para> </para>
        /// If generation failed for some reason, <c>null</c> is returned.
        /// </summary>
        /// <param name="rsaKeySize">The desired RSA key size (in bits).</param>
        /// <returns>The RSA key pair <see cref="Tuple"/>, where the first item is the public key and the second is the private key. If generation failed for some reason, <c>null</c> is returned.</returns>
        public Task<Tuple<string, string>> GenerateKeyPair(RSAKeySize rsaKeySize = RSAKeySize.RSA2048bit)
        {
            return Task.Run(() =>
            {
                try
                {
                    var keygen = new RsaKeyPairGenerator();
                    keygen.Init(new KeyGenerationParameters(new SecureRandom(), (int)rsaKeySize));
                    AsymmetricCipherKeyPair keyPair = keygen.GenerateKeyPair();
                    return new Tuple<string, string>(keyPair.Public.ToPemString(), keyPair.Private.ToPemString());
                }
                catch (Exception e)
                {
                    logger?.LogError($"{nameof(AsymmetricKeygenRSA)}::{nameof(GenerateKeyPair)}: RSA key pair generation failed. Thrown exception: {e}");
                    return null;
                }
            });
        }
    }
}