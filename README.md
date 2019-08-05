[![NuGet](https://img.shields.io/nuget/v/GlitchedPolygons.Services.Cryptography.Asymmetric.svg)](https://www.nuget.org/packages/GlitchedPolygons.Services.Cryptography.Asymmetric)
[![API](https://img.shields.io/badge/api-docs-informational)](https://glitchedpolygons.github.io/Cryptography.Asymmetric/api/GlitchedPolygons.Services.Cryptography.Asymmetric.html) [![CircleCI](https://circleci.com/gh/GlitchedPolygons/Cryptography.Asymmetric.svg?style=shield)](https://circleci.com/gh/GlitchedPolygons/Cryptography.Asymmetric) [![Travis Build Status](https://travis-ci.org/GlitchedPolygons/Cryptography.Asymmetric.svg?branch=master)](https://travis-ci.org/GlitchedPolygons/Cryptography.Asymmetric)

# Asymmetric Cryptography (RSA)

## Encrypting, decrypting, signing and verifying data made easy.

#### Namespace:  `GlitchedPolygons.Services.Cryptography.Asymmetric`

This is a simple, easy-to-use crypto library for C# ([netstandard2.0](https://github.com/dotnet/standard/blob/master/docs/versions/netstandard2.0.md)).

It makes use of the portable [BouncyCastle](https://www.bouncycastle.org/) NuGet package to provide a reliable cross-platform cryptography interface.

You can encrypt, decrypt, sign and verify `string` and `byte[]` arrays with ease. The interfaces and their implementations are also IoC friendly, so you can inject them into your favorite DI containers (e.g. in [ASP.NET Core MVC](https://docs.microsoft.com/en-us/aspnet/core/mvc/overview?view=aspnetcore-2.2) apps you'd use `services.AddTransient` inside _Startup.cs_).

The `IAsymmetricCryptographyRSA` interface provides functionality for all basic asymmetric RSA crypto operations you need for your C# project. 
RSA keys can be generated in variable key sizes and exported into comfortable PEM strings using `IAsymmetricKeygenRSA`.
For more information, check out the [API Documentation](https://glitchedpolygons.github.io/Cryptography.Asymmetric/api/GlitchedPolygons.Services.Cryptography.Asymmetric.html).

**Technology used:**
* C# ([netstandard2.0](https://github.com/dotnet/standard/blob/master/docs/versions/netstandard2.0.md))
* [Portable.BouncyCastle](https://github.com/onovotny/bc-csharp)
* [Microsoft.Extensions.Logging](https://github.com/aspnet/Extensions/tree/master/src/Logging)

---

API docs can be found here:
_[glitchedpolygons.github.io/Cryptography.Asymmetric](https://glitchedpolygons.github.io/Cryptography.Asymmetric/api/GlitchedPolygons.Services.Cryptography.Asymmetric.html)_
