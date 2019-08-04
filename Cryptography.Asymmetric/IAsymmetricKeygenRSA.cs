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
        /// Generates a new RSA key pair <see cref="Tuple"/>.
        /// </summary>
        /// <returns>The key pair <see cref="Tuple"/>, where the first item is the public RSA key and the second is the private key (both PEM-formatted).</returns>
        Task<Tuple<string, string>> GenerateKeyPair();
    }
}