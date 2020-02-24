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
using Org.BouncyCastle.Security;

namespace GlitchedPolygons.Services.Cryptography.Asymmetric
{
    /// <summary>
    /// Represents an RSA key's size.<para> </para>
    /// Possible values are 512-bit, 1024-bit, 2048-bit and 4096-bit.<para> </para>
    /// The bigger, the slower, the safer.
    /// </summary>
    public abstract class RSAKeySize
    {
        /// <summary>
        /// The underlying key size in bits.
        /// </summary>
        private readonly int size;

        /// <summary>
        /// Constructs an instance of <see cref="RSAKeySize"/>
        /// using the provided "<paramref name="size"/>" key size
        /// in bits (which must be either 512, 1024, 2048 or 4096).
        /// </summary>
        /// <param name="size">RSA key size in bits. Can only be 512, 1024, 2048 or 4096.</param>
        protected internal RSAKeySize(int size)
        {
            if (size % 512 != 0 || size < 512 || size > 4096)
            {
                throw new InvalidKeyException($"{nameof(RSAKeySize)}::ctor: The specified key size \"{size}\" is not a valid RSA key size. Valid sizes are 512, 1024, 2048 and 4096-bit.");
            }
            this.size = size;
        }

        /// <summary>
        /// Converts an instance of <see cref="RSAKeySize"/> to the corresponding key size <c>int</c>.
        /// </summary>
        /// <param name="keySize">The <see cref="RSAKeySize"/> to convert.</param>
        /// <returns>The converted key size <c>int</c> in bits.</returns>
        /// <exception cref="InvalidKeyException">Thrown when the passed key size is invalid: the only valid key sizes are 512, 1024, 2048 and 4096-bit.</exception>
        public static implicit operator int(RSAKeySize keySize) => keySize.size;
    }

    /// <summary>
    /// 512-bit RSA Key.
    /// </summary>
    [Obsolete]
    public sealed class RSA512 : RSAKeySize
    {
        /// <summary>
        /// Constructs a 512-bit <see cref="RSAKeySize"/>.
        /// </summary>
        public RSA512() : base(512) { }
    }

    /// <summary>
    /// 1024-bit RSA Key.
    /// </summary>
    public sealed class RSA1024 : RSAKeySize
    {
        /// <summary>
        /// Constructs a 1024-bit <see cref="RSAKeySize"/>.
        /// </summary>
        public RSA1024() : base(1024) { }
    }

    /// <summary>
    /// 2048-bit RSA Key.
    /// </summary>
    public sealed class RSA2048 : RSAKeySize
    {
        /// <summary>
        /// Constructs a 2048-bit <see cref="RSAKeySize"/>.
        /// </summary>
        public RSA2048() : base(2048) { }
    }

    /// <summary>
    /// 4096-bit RSA Key.
    /// </summary>
    public sealed class RSA4096 : RSAKeySize
    {
        /// <summary>
        /// Constructs a 4096-bit <see cref="RSAKeySize"/>.
        /// </summary>
        public RSA4096() : base(4096) { }
    }
}
