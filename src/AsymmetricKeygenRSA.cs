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
    /// <seealso cref="RSAKeySize"/>
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
        /// Generates a new RSA key pair <see cref="Tuple"/> using the provided RSA key size parameter <paramref name="keySize"/>.<para> </para>
        /// Returns the RSA key pair <see cref="Tuple"/>, where the first item is the public key and the second is the private key.<para> </para>
        /// If generation failed for some reason, <c>null</c> is returned.
        /// </summary>
        /// <param name="keySize">The desired RSA key size. Can be 512-bit, 1024-bit, 2048-bit or 4096-bit.</param>
        /// <returns>The key pair <see cref="Tuple"/>, where the first item is the public RSA key and the second one is the private key (both PEM-formatted).</returns>
        public Task<Tuple<string, string>> GenerateKeyPair(RSAKeySize keySize) 
        {
            return Task.Run(() =>
            {
                try
                {
                    var keygen = new RsaKeyPairGenerator();
                    keygen.Init(new KeyGenerationParameters(new SecureRandom(), keySize));
                    AsymmetricCipherKeyPair keyPair = keygen.GenerateKeyPair();
                    return new Tuple<string, string>(keyPair.Public.ToPemString(), keyPair.Private.ToPemString());
                }
                catch (Exception e)
                {
                    logger?.LogError($"{nameof(AsymmetricKeygenRSA)}::{nameof(GenerateKeyPair)}: RSA key pair generation failed. Thrown exception: {e.ToString()}");
                    return null;
                }
            });
        }
    }
}
