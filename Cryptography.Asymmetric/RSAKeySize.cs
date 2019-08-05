using System;

namespace GlitchedPolygons.Services.Cryptography.Asymmetric
{
    /// <summary>
    /// Represents an RSA key's size.<para> </para>
    /// Possible values are 512-bit, 1024-bit, 2048-bit and 4096-bit.
    /// The bigger, the slower, the safer.
    /// </summary>
    public enum RSAKeySize : int
    {
        [Obsolete]
        RSA512bit = 512,
        
        /// <summary>
        /// 1024-bit RSA Key
        /// </summary>
        RSA1024bit = 1024,
        
        /// <summary>
        /// 2048-bit RSA Key
        /// </summary>
        RSA2048bit = 2048,
        
        /// <summary>
        /// 4096-bit RSA Key
        /// </summary>
        RSA4096bit = 4096
    }
}
