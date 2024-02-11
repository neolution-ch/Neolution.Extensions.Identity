# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added logging to all `UserManager` methods
- Added `TokenSignInManager` to issue access tokens and external sign-in via ID token
- Added support for Google OpenID connect in `TokenSignInManager`
- Added `SignInManager` facade and exposed `PreSignInCheck` method
- Added BCrypt implementation of the IdentityPasswordHasher

### Changed

- Updated all dependencies to latest minor version
- Changed Github workflows for new release management
- Use `Microsoft.NET.Sdk.Web` for the package

### Removed

- Removed unnecessary dependencies from the Abstractions package
