/*
   Copyright 2020 Raphael Beck

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

using System;
using System.Threading.Tasks;

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;

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
        private readonly Action<string> errorCallback;
        
        /// <summary>
        /// Creates a new asymmetric RSA key generator.
        /// <param name="errorCallback">Optional callback for when an exception is thrown during key generation (could be fed back to your own personal error logging provider for example). The passed <c>string</c> parameter is the error message, including the full exception's content...</param>
        /// </summary>
        public AsymmetricKeygenRSA(Action<string> errorCallback = null)
        {
            this.errorCallback = errorCallback;
        }

        /// <summary>
        /// Generates a new RSA key pair <see cref="Tuple"/> using the provided RSA key size parameter <paramref name="keySize"/>.<para> </para>
        /// Returns the RSA key pair <see cref="Tuple"/>, where the first item is the public key and the second is the private key.<para> </para>
        /// If generation failed for some reason, <c>null</c> is returned.
        /// </summary>
        /// <param name="keySize">The desired RSA key size. Can be 512-bit, 1024-bit, 2048-bit or 4096-bit.</param>
        /// <returns>The key pair <see cref="Tuple"/>, where the first item is the public RSA key and the second one is the private key (both PEM-formatted). If key generation failed, both tuple items are <c>null</c>.</returns>
        public Task<ValueTuple<string, string>> GenerateKeyPair(RSAKeySize keySize) 
        {
            return Task.Run(() =>
            {
                try
                {
                    var keygen = new RsaKeyPairGenerator();
                    keygen.Init(new KeyGenerationParameters(new SecureRandom(), (int)keySize));
                    AsymmetricCipherKeyPair keyPair = keygen.GenerateKeyPair();
                    return (keyPair.Public.ToPemString(), keyPair.Private.ToPemString());
                }
                catch (Exception e)
                {
                    errorCallback?.Invoke($"{nameof(AsymmetricKeygenRSA)}::{nameof(GenerateKeyPair)}: RSA key pair generation failed. Thrown exception: {e.ToString()}");
                    return (null, null);
                }
            });
        }
    }
}
