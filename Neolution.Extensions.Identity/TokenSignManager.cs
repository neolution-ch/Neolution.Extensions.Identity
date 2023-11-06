﻿namespace Neolution.Extensions.Identity
{
    using System.Security.Claims;
    using Google.Apis.Auth;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.Extensions.Options;
    using Neolution.Extensions.Identity.Abstractions;
    using Neolution.Extensions.Identity.Abstractions.Options;
    using JsonWebToken = Neolution.Extensions.Identity.Abstractions.JsonWebToken;

    /// <inheritdoc />
    public sealed class TokenSignManager<TUser> : ITokenSignInManager<TUser>
        where TUser : IdentityUser<Guid>
    {
        /// <summary>
        /// The logger
        /// </summary>
        private readonly ILogger<TokenSignManager<TUser>> logger;

        /// <summary>
        /// The user manager
        /// </summary>
        private readonly IUserManager<TUser> userManager;

        /// <summary>
        /// The sign in manager
        /// </summary>
        private readonly ISignInManager<TUser> signInManager;

        /// <summary>
        /// The JWT generator
        /// </summary>
        private readonly IJwtGenerator<TUser> jwtGenerator;

        /// <summary>
        /// The Identity options
        /// </summary>
        private readonly NeolutionIdentityOptions options;

        /// <summary>
        /// Initializes a new instance of the <see cref="TokenSignManager{TUser}" /> class.
        /// </summary>
        /// <param name="logger">The logger.</param>
        /// <param name="userManager">The user manager.</param>
        /// <param name="signInManager">The sign in manager.</param>
        /// <param name="jwtGenerator">The JWT generator.</param>
        /// <param name="options">The Identity options.</param>
        public TokenSignManager(ILogger<TokenSignManager<TUser>> logger, IUserManager<TUser> userManager, ISignInManager<TUser> signInManager, IJwtGenerator<TUser> jwtGenerator, IOptions<NeolutionIdentityOptions> options)
        {
            this.logger = logger;
            this.userManager = userManager;
            this.signInManager = signInManager;
            this.jwtGenerator = jwtGenerator;
            this.options = options.Value;
        }

        /// <inheritdoc />
        public async Task<TUser?> PasswordSignInAsync(string username, string password)
        {
            this.logger.LogTrace("Perform password sign-in for user={User}", username);
            var user = await this.userManager.FindByEmailAsync(username);
            if (user == null)
            {
                this.logger.LogInformation("Could not find user by email address '{Email}'", username);
                return null;
            }

            var signInResponse = await this.signInManager.CheckPasswordSignInAsync(user, password, true);
            if (signInResponse.Succeeded)
            {
                this.logger.LogTrace("Password sign-in for user={User} succeeded", username);
                return user;
            }

            this.logger.LogWarning("Password sign-in for user={User} failed", username);
            return null;
        }

        /// <inheritdoc />
        public async Task<TUser?> GoogleSignInAsync(string token)
        {
            this.logger.LogTrace("Perform sign-in with Google ID token");
            if (string.IsNullOrWhiteSpace(this.options.Google?.ClientId))
            {
                this.logger.LogError("Google ClientId must be defined to enable ID token sign-in");
                return null;
            }

            var validationSettings = new GoogleJsonWebSignature.ValidationSettings
            {
                Audience = new List<string> { this.options.Google.ClientId },
            };

            try
            {
                var payload = await GoogleJsonWebSignature.ValidateAsync(token, validationSettings); // Will throw an exception if validation fails.
                this.logger.LogInformation("ID token is valid for user with email={Email}", payload.Email);

                // TODO: Think about different discovery options for external users
                var user = await this.userManager.FindByEmailAsync(payload.Email);
                if (user is null)
                {
                    this.logger.LogInformation("Could not find user by email address '{Email}'", payload.Email);
                    return null;
                }

                var error = await this.signInManager.PreSignInCheckAsync(user);
                if (error != null)
                {
                    this.logger.LogInformation("Could not sign-in user with id={UserId} as he failed the pre-sign-in check", payload.Email);
                    return null;
                }

                this.logger.LogWarning("Password sign-in for user with id={UserId} failed", user.Id);
                return user;
            }
            catch (Exception ex)
            {
                this.logger.LogError(ex, "Could not sign in user with Google ID token");
                return null;
            }
        }

        /// <inheritdoc />
        public async Task<JsonWebToken?> CreateAccessTokenAsync(TUser user)
        {
            return await this.CreateAccessTokenAsync(user, null);
        }

        /// <inheritdoc />
        public async Task<JsonWebToken?> CreateAccessTokenAsync(TUser user, string? authenticationMethod)
        {
            this.logger.LogInformation("Create access token for user with id={UserId} and authentication method {AuthenticationMethod}", user.Id, authenticationMethod);
            var claims = await this.userManager.GetClaimsAsync(user);
            if (authenticationMethod != null)
            {
                claims.Add(new Claim(ClaimTypes.AuthenticationMethod, authenticationMethod));
            }

            return this.jwtGenerator.GenerateAccessToken(user, claims);
        }
    }
}
