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
using System.IO;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;

namespace GlitchedPolygons.Services.Cryptography.Asymmetric
{
    /// <summary>
    /// Extension methods for <see cref="Org.BouncyCastle.Crypto.AsymmetricKeyParameter"/>.
    /// <seealso cref="RSAKeySize"/>
    /// <seealso cref="AsymmetricKeyParameter"/>
    /// <seealso cref="IAsymmetricKeygenRSA"/>
    /// <seealso cref="IAsymmetricCryptographyRSA"/>
    /// </summary>
    public static class AsymmetricKeyParameterExtensions
    {
        /// <summary>
        /// Converts a BouncyCastle <see cref="AsymmetricKeyParameter"/> to a PEM-formatted <c>string</c>.
        /// </summary>
        /// <param name="key">The key to stringify.</param>
        /// <returns><c>string</c> containing the PEM-formatted key.</returns>
        public static string ToPemString(this AsymmetricKeyParameter key)
        {
            using (var sw = new StringWriter())
            {
                var pem = new PemWriter(sw);
                pem.WriteObject(key);
                pem.Writer.Flush();
                return sw.ToString();
            }
        }
    }
}