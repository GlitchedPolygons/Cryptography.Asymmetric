using System;
using System.Threading.Tasks;

namespace GlitchedPolygons.Services.Cryptography.Asymmetric
{
    /// <summary>
    /// Asymmetric RSA key generator.
    /// </summary>
    public interface IAsymmetricKeygenRSA
    {
        /// <summary>
        /// Generates a new RSA key pair <see cref="Tuple"/> using the provided RSA key size parameter "<paramref name="rsaKeySize"/>".
        /// Returns the RSA key pair <see cref="Tuple"/>, where the first item is the public key and the second is the private key.<para> </para>
        /// If generation failed for some reason, <c>null</c> is returned.
        /// </summary>
        /// <param name="rsaKeySize">The desired RSA key size (can be 512-bit, 1024-bit, 2048-bit or 4096-bit).</param>
        /// <returns>The key pair <see cref="Tuple"/>, where the first item is the public RSA key and the second is the private key (both PEM-formatted).</returns>
        Task<Tuple<string, string>> GenerateKeyPair(RSAKeySize rsaKeySize = RSAKeySize.RSA2048bit);
    }
}