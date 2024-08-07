# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added logging to all `UserManager` methods
- Added `TokenSignInManager` to issue access tokens and external sign-in via ID token
- Added `IJwtGenerator` interface so developers can control how access tokens are generated
- Added `SignInManager` facade and exposed `PreSignInCheck` method
- Added BCrypt implementation of the IdentityPasswordHasher
- Added dedicated `NeolutionIdentity` configuration section to for package-specific settings

### Changed

- Upgraded to .NET 8
- Updated all dependencies to latest minor version
- Changed Github workflows for new release management
- Use `Microsoft.NET.Sdk.Web` for the main package
- Replaced `JsonWebToken` with custom implementation which uses `DateTimeOffset` for the expiration date
- Replaced Google-specific OpenID Connect implementation with a generic one that can be extended in the future
