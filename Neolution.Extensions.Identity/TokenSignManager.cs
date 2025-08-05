namespace Neolution.Extensions.Identity
{
    using System.IdentityModel.Tokens.Jwt;
    using System.Security.Claims;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.IdentityModel.Protocols;
    using Microsoft.IdentityModel.Protocols.OpenIdConnect;
    using Microsoft.IdentityModel.Tokens;
    using Neolution.Extensions.Identity.Abstractions;
    using Neolution.Extensions.Identity.Abstractions.OpenIdConnect;
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
        /// Initializes a new instance of the <see cref="TokenSignManager{TUser}" /> class.
        /// </summary>
        /// <param name="logger">The logger.</param>
        /// <param name="userManager">The user manager.</param>
        /// <param name="signInManager">The sign in manager.</param>
        /// <param name="jwtGenerator">The JWT generator.</param>
        public TokenSignManager(ILogger<TokenSignManager<TUser>> logger, IUserManager<TUser> userManager, ISignInManager<TUser> signInManager, IJwtGenerator<TUser> jwtGenerator)
        {
            this.logger = logger;
            this.userManager = userManager;
            this.signInManager = signInManager;
            this.jwtGenerator = jwtGenerator;
        }

        /// <inheritdoc />
        public async Task<JsonWebToken?> PasswordSignInAsync(TUser user, string password)
        {
            this.logger.LogTrace("Perform password sign-in for user email={Email}/username={Username}", user.Email, user.UserName);
            var signInResponse = await this.signInManager.CheckPasswordSignInAsync(user, password, true);
            if (signInResponse.Succeeded)
            {
                return await this.CreateAccessTokenAsync(user, "pwd", "identity-store");
            }

            this.logger.LogWarning("Password sign-in for user email={Email}/username={Username} failed", user.Email, user.UserName);
            return null;
        }

        /// <inheritdoc />
        public async Task<JsonWebToken?> PasswordSignInAsync(string email, string password)
        {
            this.logger.LogTrace("Perform password sign-in for user email={User}", email);
            var user = await this.userManager.FindByEmailAsync(email);
            if (user == null)
            {
                return null;
            }

            return await this.PasswordSignInAsync(user, password);
        }

        /// <inheritdoc />
        public async Task<JsonWebToken?> TwoFactorAuthenticatorSignInAsync(Guid userId, string code, string authenticationMethod)
        {
            this.logger.LogTrace("Perform two factor sign-in for user id={UserId}", userId);
            var user = await this.userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return null;
            }

            var preSignInRespone = await this.signInManager.PreSignInCheckAsync(user);
            if (!preSignInRespone.Succeeded)
            {
                return null;
            }

            var mfaTokenVerified = await this.userManager.VerifyTwoFactorTokenAsync(user, TokenOptions.DefaultAuthenticatorProvider, code);
            if (!mfaTokenVerified)
            {
                return null;
            }

            var resetLockoutResult = await this.ResetLockoutWithResultAsync(user);
            if (!resetLockoutResult.Succeeded)
            {
                // If the token is incorrect, record the failure which also may cause the user to be locked out
                var incrementLockoutResult = await this.userManager.AccessFailedAsync(user) ?? IdentityResult.Success;
                if (!incrementLockoutResult.Succeeded)
                {
                    // Return the same failure we do when resetting the lockout fails after a correct two factor code.
                    // This is currently redundant, but it's here in case the code gets copied elsewhere.
                    return null;
                }

                // ResetLockout got an unsuccessful result that could be caused by concurrency failures indicating an
                // attacker could be trying to bypass the MaxFailedAccessAttempts limit. Return the same failure we do
                // when failing to increment the lockout to avoid giving an attacker extra guesses at the two factor code.
                return null;
            }

            return await this.CreateAccessTokenAsync(user, "mfa", authenticationMethod);
        }

        /// <inheritdoc />
        public async Task<TUser?> OpenIdConnectSignInAsync(OpenIdConnectToken token)
        {
            this.logger.LogTrace("Perform sign-in with OIDC token");

            try
            {
                var claimsPrincipal = await this.ValidateOpenIdConnectInfoAsync(token);

                var email = claimsPrincipal.Claims.Where(x => x.Type == ClaimTypes.Email).Select(x => x.Value).FirstOrDefault();
                if (email == null)
                {
                    this.logger.LogInformation("Could not find email claim in ID token");
                    return null;
                }

                // Continue with the rest of your sign-in logic
                this.logger.LogInformation("OIDC token is valid for user with email={Email}", email);

                // TODO: Think about different discovery options for external users
                var user = await this.userManager.FindByEmailAsync(email);
                if (user is null)
                {
                    return null;
                }

                var preSignInRespone = await this.signInManager.PreSignInCheckAsync(user);
                if (!preSignInRespone.Succeeded)
                {
                    return null;
                }

                return user;
            }
            catch (Exception ex)
            {
                this.logger.LogError(ex, "Could not sign in user with OIDC token");
                return null;
            }
        }

        /// <inheritdoc />
        public async Task<JsonWebToken?> CreateAccessTokenAsync(TUser user, string amr, string authenticationMethod)
        {
            this.logger.LogInformation("Create access token for user with id={UserId}", user.Id);
            var claims = await this.userManager.GetClaimsAsync(user);
            if (authenticationMethod != null)
            {
                this.logger.LogInformation("Set authentication method to {AuthenticationMethod}", authenticationMethod);
                claims.Add(new Claim(ClaimTypes.AuthenticationMethod, authenticationMethod));
            }

            return this.jwtGenerator.GenerateAccessToken(user, claims, amr);
        }

        /// <summary>
        /// Resets the lockout of the specified user.
        /// </summary>
        /// <param name="user">The user.</param>
        /// <returns>The identity result.</returns>
        private async Task<IdentityResult> ResetLockoutWithResultAsync(TUser user)
        {
            if (!this.userManager.SupportsUserLockout)
            {
                this.logger.LogTrace("User lockout is disabled, did not reset lockout for user id={UserId}", user.Id);
                return IdentityResult.Success;
            }

            return await this.userManager.ResetAccessFailedCountAsync(user) ?? IdentityResult.Success;
        }

        /// <summary>
        /// Validates the OpenID connect token. Throws an exception if the token is invalid.
        /// </summary>
        /// <param name="token">The token.</param>
        /// <returns>The <see cref="ClaimsPrincipal"/>.</returns>
        private async Task<ClaimsPrincipal> ValidateOpenIdConnectInfoAsync(OpenIdConnectToken token)
        {
            var configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(token.ValidationOptions.DiscoveryDocumentUrl, new OpenIdConnectConfigurationRetriever(), new HttpDocumentRetriever());
            var discoveryDocument = await configurationManager.GetConfigurationAsync(CancellationToken.None);
            var signingKeys = discoveryDocument.SigningKeys;

            var validationParameters = new TokenValidationParameters
            {
                ValidAudience = token.ValidationOptions.ClientId,
                ValidIssuer = token.ValidationOptions.Issuer,
                IssuerSigningKeys = signingKeys,
                ValidateIssuer = token.ValidationOptions.ValidateIssuer,

                // Additional validation parameters as necessary
            };

            return new JwtSecurityTokenHandler().ValidateToken(token.IdToken, validationParameters, out _);
        }
    }
}
