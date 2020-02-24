[![NuGet](https://buildstats.info/nuget/GlitchedPolygons.Services.Cryptography.Asymmetric)](https://www.nuget.org/packages/GlitchedPolygons.Services.Cryptography.Asymmetric)
[![API](https://img.shields.io/badge/api-docs-informational)](https://glitchedpolygons.github.io/Cryptography.Asymmetric/api/GlitchedPolygons.Services.Cryptography.Asymmetric.html) 
[![License Shield](https://img.shields.io/badge/license-Apache--2.0-orange)](https://github.com/GlitchedPolygons/Cryptography.Asymmetric/blob/master/LICENSE)
[![AppVeyor](https://ci.appveyor.com/api/projects/status/y5873yb3icfdjqp2/branch/master?svg=true)](https://ci.appveyor.com/project/GlitchedPolygons/cryptography-asymmetric/branch/master)
[![Travis Build Status](https://travis-ci.org/GlitchedPolygons/Cryptography.Asymmetric.svg?branch=master)](https://travis-ci.org/GlitchedPolygons/Cryptography.Asymmetric)
[![CircleCI](https://circleci.com/gh/GlitchedPolygons/Cryptography.Asymmetric.svg?style=shield)](https://circleci.com/gh/GlitchedPolygons/Cryptography.Asymmetric)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/af5f70aa367443d88341549cdc6fa566)](https://www.codacy.com/manual/GlitchedPolygons/Cryptography.Asymmetric?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=GlitchedPolygons/Cryptography.Asymmetric&amp;utm_campaign=Badge_Grade)

# Asymmetric Cryptography (RSA)

## Encrypting, decrypting, signing and verifying data made easy.

#### Namespace:  `GlitchedPolygons.Services.Cryptography.Asymmetric`

This is a simple, easy-to-use crypto library for C# 8.0 ([netstandard2.1](https://github.com/dotnet/standard/blob/master/docs/versions/netstandard2.1.md)).

It makes use of the portable [BouncyCastle](https://www.bouncycastle.org/) NuGet package to provide a reliable cross-platform cryptography interface.

You can encrypt, decrypt, sign and verify `string` and `byte[]` arrays with ease. The interfaces and their implementations are also IoC friendly, so you can inject them into your favorite DI containers (e.g. in [ASP.NET Core MVC](https://docs.microsoft.com/en-us/aspnet/core/mvc/overview?view=aspnetcore-2.2) apps you'd use `services.AddTransient` inside _Startup.cs_).

The `IAsymmetricCryptographyRSA` interface provides functionality for all basic asymmetric RSA crypto operations you need for your C# project. 
RSA keys can be generated in variable key sizes and exported into comfortable PEM strings using `IAsymmetricKeygenRSA`.
For more information, check out the [API Documentation](https://glitchedpolygons.github.io/Cryptography.Asymmetric/api/GlitchedPolygons.Services.Cryptography.Asymmetric.html).

**Technology used:**
* C# ([netstandard2.1](https://github.com/dotnet/standard/blob/master/docs/versions/netstandard2.1.md))
* [Portable.BouncyCastle](https://github.com/onovotny/bc-csharp)

---

API docs can be found here:
_[glitchedpolygons.github.io/Cryptography.Asymmetric](https://glitchedpolygons.github.io/Cryptography.Asymmetric/api/GlitchedPolygons.Services.Cryptography.Asymmetric.html)_
