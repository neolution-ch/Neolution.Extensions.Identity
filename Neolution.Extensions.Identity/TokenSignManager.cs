namespace Neolution.Extensions.Identity
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
        public async Task<JsonWebToken?> PasswordSignInAsync(string email, string password)
        {
            this.logger.LogTrace("Perform password sign-in for user email={User}", email);
            var user = await this.userManager.FindByEmailAsync(email);
            if (user == null)
            {
                return null;
            }

            var signInResponse = await this.signInManager.CheckPasswordSignInAsync(user, password, true);
            if (signInResponse.Succeeded)
            {
                return await this.CreateAccessTokenAsync(user, null);
            }

            this.logger.LogWarning("Password sign-in for user email={User} failed", email);
            return null;
        }

        /// <inheritdoc />
        public async Task<JsonWebToken?> TwoFactorAuthenticatorSignInAsync(Guid userId, string code, string? authenticationMethod)
        {
            this.logger.LogTrace("Perform two factor sign-in for user id={UserId}", userId);
            var user = await this.userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return null;
            }

            var error = await this.signInManager.PreSignInCheckAsync(user);
            if (error != null)
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

            var claims = new List<Claim>();
            if (authenticationMethod != null)
            {
                claims.Add(new Claim(ClaimTypes.AuthenticationMethod, authenticationMethod));
            }

            return this.jwtGenerator.GenerateAccessToken(user, claims, "mfa");
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

            var payload = await GoogleJsonWebSignature.ValidateAsync(token, validationSettings); // Will throw an exception if validation fails.
            this.logger.LogInformation("Google ID token is valid for user with email={Email}", payload.Email);

            try
            {
                // TODO: Think about different discovery options for external users
                var user = await this.userManager.FindByEmailAsync(payload.Email);
                if (user is null)
                {
                    return null;
                }

                var error = await this.signInManager.PreSignInCheckAsync(user);
                if (error != null)
                {
                    return null;
                }

                return user;
            }
            catch (Exception ex)
            {
                this.logger.LogError(ex, "Could not sign in user despite valid Google ID token");
                return null;
            }
        }

        /// <inheritdoc />
        public async Task<JsonWebToken?> CreateAccessTokenAsync(TUser user, string? authenticationMethod)
        {
            this.logger.LogInformation("Create access token for user with id={UserId}", user.Id);
            var claims = await this.userManager.GetClaimsAsync(user);
            if (authenticationMethod != null)
            {
                this.logger.LogInformation("Set authentication method to {AuthenticationMethod}", authenticationMethod);
                claims.Add(new Claim(ClaimTypes.AuthenticationMethod, authenticationMethod));
            }

            return this.jwtGenerator.GenerateAccessToken(user, claims);
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
    }
}
