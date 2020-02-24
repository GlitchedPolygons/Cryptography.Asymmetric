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

using Xunit;
using System;
using System.IO;
using System.Threading.Tasks;

namespace GlitchedPolygons.Services.Cryptography.Asymmetric.Tests
{
    public class AsymmetricCryptographyRSATests
    {
        private static readonly RSAKeySize KEY_SIZE_512 = new RSA512();
        private static readonly RSAKeySize KEY_SIZE_1024 = new RSA1024();
        private static readonly RSAKeySize KEY_SIZE_2048 = new RSA2048();
        private static readonly RSAKeySize KEY_SIZE_4096 = new RSA4096();
        
        private readonly IAsymmetricKeygenRSA keygen = new AsymmetricKeygenRSA();
        private readonly IAsymmetricCryptographyRSA crypto = new AsymmetricCryptographyRSA();
        
        private readonly string text = Guid.NewGuid().ToString("D");
        private readonly string privateKeyPem1 = File.ReadAllText("TestData/KeyPair1/Private");
        private readonly string publicTestKeyPem1 = File.ReadAllText("TestData/KeyPair1/Public");
        private readonly string privateKeyPem2 = File.ReadAllText("TestData/KeyPair2/Private");
        private readonly string publicTestKeyPem2 = File.ReadAllText("TestData/KeyPair2/Public");
        
        private readonly byte[] data = new byte[] { 1, 2, 3, 64, 128, 1, 3, 3, 7, 6, 9, 4, 2, 0, 1, 9, 9, 6, 58, 67, 55, 100, 96 };

        private Task<ValueTuple<string,string>> FreshKeys(int keySize)
        {
            var rsaKeySize = KEY_SIZE_1024;
            switch (keySize)
            {
                case 512: rsaKeySize = KEY_SIZE_512;
                    break;
                case 1024: rsaKeySize = KEY_SIZE_1024;
                    break;
                case 2048: rsaKeySize = KEY_SIZE_2048;
                    break;
                case 4096: rsaKeySize = KEY_SIZE_4096;
                    break;
            }
            return keygen.GenerateKeyPair(rsaKeySize);
        }


        [Theory]
        [InlineData(512)]
        [InlineData(1024)]
        [InlineData(2048)]
        [InlineData(4096)]
        public async Task AsymmetricCryptography_EncryptString_DecryptString_IdenticalAfterwards(int keySize)
        {
            var keys = await FreshKeys(keySize);
            string encr = crypto.Encrypt(text, keys.Item1);
            string decr = crypto.Decrypt(encr, keys.Item2);
            Assert.Equal(decr, text);
        }
        
        [Fact]
        public void AsymmetricCryptography_EncryptStringUsingTestKey1_DecryptString_IdenticalAfterwards()
        {
            string encr = crypto.Encrypt(text, publicTestKeyPem1);
            string decr = crypto.Decrypt(encr, privateKeyPem1);
            Assert.Equal(decr, text);
        }
        
        [Fact]
        public void AsymmetricCryptography_EncryptStringUsingTestKey2_DecryptString_IdenticalAfterwards()
        {
            string encr = crypto.Encrypt(text, publicTestKeyPem2);
            string decr = crypto.Decrypt(encr, privateKeyPem2);
            Assert.Equal(decr, text);
        }

        [Theory]
        [InlineData(512)]
        [InlineData(1024)]
        [InlineData(2048)]
        [InlineData(4096)]
        public async Task AsymmetricCryptography_EncryptStringUsingPrivateKey_DecryptString_IdenticalAfterwards_ShouldAlsoWork(int keySize)
        {
            var keys = await FreshKeys(keySize);
            string encr = crypto.Encrypt(text, keys.Item2);
            string decr = crypto.Decrypt(encr, keys.Item2);
            Assert.Equal(decr, text);
        }

        [Fact]
        public void AsymmetricCryptography_EncryptString_NotIdenticalWithOriginal()
        {
            string encr = crypto.Encrypt(text, publicTestKeyPem1);
            Assert.NotEqual(encr, text);
        }

        [Theory]
        [InlineData("")]
        [InlineData(null)]
        public void AsymmetricCryptography_EncryptNullOrEmptyString_ReturnsEmptyString(string s)
        {
            string encr = crypto.Encrypt(s, publicTestKeyPem1);
            Assert.Empty(encr);
        }

        [Theory]
        [InlineData("")]
        [InlineData(null)]
        public void AsymmetricCryptography_EncryptStringWithNullOrEmptyKey_ReturnsEmptyString(string s)
        {
            string encr = crypto.Encrypt(text, s);
            Assert.Empty(encr);
        }

        [Theory]
        [InlineData("")]
        [InlineData(null)]
        public void AsymmetricCryptography_DecryptNullOrEmptyString_ReturnsEmptyString(string s)
        {
            string decr = crypto.Decrypt(s, publicTestKeyPem1);
            Assert.Empty(decr);
        }

        [Theory]
        [InlineData("")]
        [InlineData(null)]
        public void AsymmetricCryptography_DecryptStringWithNullOrEmptyKey_ReturnsEmptyString(string s)
        {
            string decr = crypto.Decrypt(text, s);
            Assert.Empty(decr);
        }

        [Theory]
        [InlineData(512)]
        [InlineData(1024)]
        [InlineData(2048)]
        [InlineData(4096)]
        public async Task AsymmetricCryptography_EncryptString_DecryptStringUsingPublicKey_ReturnsNull(int keySize)
        {
            var keys = await FreshKeys(keySize);
            string encr = crypto.Encrypt(text, keys.Item1);
            string decr = crypto.Decrypt(encr, keys.Item1);
            Assert.NotEqual(text, decr);
            Assert.Null(decr);
        }

        [Fact]
        public void AsymmetricCryptography_EncryptString_DecryptUsingGarbageString_ReturnsNull()
        {
            string encr = crypto.Encrypt(text, publicTestKeyPem1);
            string decr = crypto.Decrypt(encr, "LOL");
            Assert.NotEqual(text, decr);
            Assert.Null(decr);
        }

        [Fact]
        public void AsymmetricCryptography_EncryptStringUsingInvalidGarbageString_DecryptionFails_ReturnsNull()
        {
            string encr = crypto.Encrypt(text, "LOL");
            string decr = crypto.Decrypt(encr, publicTestKeyPem1);
            Assert.NotEqual(text, decr);
            Assert.Null(encr);
            Assert.Empty(decr);
        }

        [Theory]
        [InlineData("")]
        [InlineData(null)]
        public void AsymmetricCryptography_SignNullOrEmptyString_ReturnsEmptyString(string txt)
        {
            string sig = crypto.Sign(txt, privateKeyPem1);
            Assert.Empty(sig);
        }

        [Theory]
        [InlineData("")]
        [InlineData(null)]
        public void AsymmetricCryptography_SignStringUsingNullOrEmptyKey_ReturnsEmptyString(string key)
        {
            string sig = crypto.Sign(text, key);
            Assert.Empty(sig);
        }

        [Theory]
        [InlineData(null)]
        [InlineData(new byte[0])]
        public void AsymmetricCryptography_SignNullOrEmptyBytes_ReturnsEmptyArray(byte[] testData)
        {
            byte[] sig = crypto.Sign(testData, privateKeyPem1);
            Assert.Empty(sig);
        }

        [Theory]
        [InlineData("")]
        [InlineData(null)]
        public void AsymmetricCryptography_SignBytesUsingNullOrEmptyKey_ReturnsEmptyString(string key)
        {
            
            byte[] sig = crypto.Sign(data, key);
            Assert.Empty(sig);
        }

        [Theory]
        [InlineData(512)]
        [InlineData(1024)]
        [InlineData(2048)]
        [InlineData(4096)]
        public async Task AsymmetricCryptography_SignStringUsingPrivateKey_VerifySignatureUsingPublicKey_ReturnsTrue_Succeeds(int keySize)
        {
            var keys = await FreshKeys(keySize);
            string sig = crypto.Sign(text, keys.Item2);
            bool verified = crypto.Verify(text, sig, keys.Item1);
            Assert.True(verified);
            Assert.NotNull(sig);
            Assert.NotEmpty(sig);
        }
        
        [Fact]
        public void AsymmetricCryptography_SignStringUsingTestKey1_VerifySignature_ReturnsTrue_Succeeds()
        {
            string sig = crypto.Sign(text, privateKeyPem1);
            bool verified = crypto.Verify(text, sig, publicTestKeyPem1);
            Assert.True(verified);
            Assert.NotNull(sig);
            Assert.NotEmpty(sig);
        }
        
        [Fact]
        public void AsymmetricCryptography_SignStringUsingTestKey2_VerifySignature_ReturnsTrue_Succeeds()
        {
            string sig = crypto.Sign(text, privateKeyPem2);
            bool verified = crypto.Verify(text, sig, publicTestKeyPem2);
            Assert.True(verified);
            Assert.NotNull(sig);
            Assert.NotEmpty(sig);
        }
        
        [Theory]
        [InlineData(512)]
        [InlineData(1024)]
        [InlineData(2048)]
        [InlineData(4096)]
        public async Task AsymmetricCryptography_SignBytes_VerifySignature_ReturnsTrue_Succeeds(int keySize)
        {
            var keys = await FreshKeys(keySize);
            byte[] sig = crypto.Sign(data, keys.Item2);
            bool verified = crypto.Verify(data, sig, keys.Item1);
            Assert.True(verified);
            Assert.NotNull(sig);
            Assert.NotEmpty(sig);
        }

        [Fact]
        public void AsymmetricCryptography_SignStringUsingPublicKey_ReturnsNull()
        {
            string sig = crypto.Sign(text, publicTestKeyPem1);
            Assert.Null(sig);
        }

        [Theory]
        [InlineData(512)]
        [InlineData(1024)]
        [InlineData(2048)]
        [InlineData(4096)]
        public async Task AsymmetricCryptography_SignBytesUsingPublicKey_ReturnsNull(int keySize)
        {
            var keys = await FreshKeys(keySize);
            byte[] sig = crypto.Sign(data, keys.Item1);
            Assert.Null(sig);
        }
        
        [Theory]
        [InlineData(512)]
        [InlineData(1024)]
        [InlineData(2048)]
        [InlineData(4096)]
        public async Task AsymmetricCryptography_SignString_VerifyUsingPrivateKey_ReturnsFalse(int keySize)
        {
            var keys = await FreshKeys(keySize);
            string sig = crypto.Sign(text, keys.Item2);
            bool verified = crypto.Verify(text, sig, keys.Item2);
            Assert.False(verified);
        }

        [Fact]
        public void AsymmetricCryptography_SignBytes_VerifyUsingPrivateKey_ReturnsFalse()
        {
            byte[] sig = crypto.Sign(data, privateKeyPem2);
            bool verified = crypto.Verify(data, sig, privateKeyPem2);
            Assert.False(verified);
        }
        
        [Fact]
        public void AsymmetricCryptography_SignString_VerifyUsingWrongKey_ReturnsFalse()
        {
            string sig = crypto.Sign(text, privateKeyPem1);
            bool verified = crypto.Verify(text, sig, publicTestKeyPem2);
            Assert.False(verified);
            Assert.NotEmpty(Convert.FromBase64String(sig));
            Assert.True(crypto.Verify(text, sig, publicTestKeyPem1));
        }
        
        [Fact]
        public void AsymmetricCryptography_SignBytes_VerifyUsingWrongKey_ReturnsFalse()
        {
            byte[] sig = crypto.Sign(data, privateKeyPem1);
            bool verified = crypto.Verify(data, sig, publicTestKeyPem2);
            Assert.False(verified);
            Assert.NotEmpty(sig);
            Assert.True(crypto.Verify(data, sig, publicTestKeyPem1));
        }
    }
}
