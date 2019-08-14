/*
   Copyright 2019 Raphael Beck

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

namespace GlitchedPolygons.Services.Cryptography.Asymmetric
{
    /// <summary>
    /// Asymmetric RSA key generator.
    /// <seealso cref="RSAKeySize"/>
    /// </summary>
    public interface IAsymmetricKeygenRSA
    {
        /// <summary>
        /// Generates a new RSA key pair <see cref="Tuple"/> using the provided RSA key size parameter <paramref name="keySize"/>.<para> </para>
        /// Returns the RSA key pair <see cref="Tuple"/>, where the first item is the public key and the second is the private key.<para> </para>
        /// If generation failed for some reason, <c>null</c> is returned.
        /// </summary>
        /// <param name="keySize">The desired RSA key size. Can be 512-bit, 1024-bit, 2048-bit or 4096-bit.</param>
        /// <returns>The key pair <see cref="Tuple"/>, where the first item is the public RSA key and the second one is the private key (both PEM-formatted).</returns>
        Task<Tuple<string, string>> GenerateKeyPair(RSAKeySize keySize);
    }
}
