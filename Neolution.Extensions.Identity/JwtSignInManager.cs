namespace Neolution.Extensions.Identity
{
    using System.Security.Claims;
    using Google.Apis.Auth;
    using Microsoft.AspNetCore.Identity;
    using Neolution.Extensions.Identity.Abstractions;
    using JsonWebToken = Neolution.Extensions.Identity.Abstractions.JsonWebToken;

    /// <inheritdoc/>
    public sealed class JwtSignInManager<TUser> : IJwtSignInManager<TUser>
        where TUser : IdentityUser<Guid>
    {
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
        /// Initializes a new instance of the <see cref="JwtSignInManager{TUser}"/> class.
        /// </summary>
        /// <param name="userManager">The user manager.</param>
        /// <param name="signInManager">The sign in manager.</param>
        /// <param name="jwtGenerator">The JWT generator.</param>
        public JwtSignInManager(IUserManager<TUser> userManager, ISignInManager<TUser> signInManager, IJwtGenerator<TUser> jwtGenerator)
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
            this.jwtGenerator = jwtGenerator;
        }

        /// <inheritdoc/>
        public async Task<JsonWebToken?> SignInWithGoogleAsync(string token, string clientId)
        {
            var validationSettings = new GoogleJsonWebSignature.ValidationSettings
            {
                Audience = new List<string> { clientId },
            };

            var payload = await GoogleJsonWebSignature.ValidateAsync(token, validationSettings); // Will throw an exception if validation fails.

            // TODO: Think about different discovery options for external users
            var user = await this.userManager.FindByEmailAsync(payload.Email);
            if (user is null)
            {
                return null;
            }

            var canSignInResult = await this.signInManager.PreSignInCheckAsync(user);
            if (canSignInResult != null)
            {
                return null;
            }

            // TODO: Decide on making this configurable
            var bypassTwoFactor = false;

            if (!bypassTwoFactor && await this.IsTfaEnabledAsync(user).ConfigureAwait(false))
            {
                // TODO: Handle TFA
                /*
                var userId = await UserManager.GetUserIdAsync(user)
                await Context.SignInAsync(IdentityConstants.TwoFactorUserIdScheme, StoreTwoFactorInfo(userId, loginProvider))
                return SignInResult.TwoFactorRequired
                */
            }

            var additionalClaims = new List<Claim>
            {
                new(ClaimTypes.AuthenticationMethod, "google"),
            };

            var claims = await this.userManager.GetClaimsAsync(user);
            additionalClaims.AddRange(claims);
            var jwt = this.jwtGenerator.GenerateAccessToken(user, additionalClaims);

            return jwt;
        }

        /// <inheritdoc/>
        public async Task<JsonWebToken?> PasswordSignInAsync(TUser user, string password)
        {
            // TODO: Decide on making this configurable
            const bool lockoutOnFailure = true;

            var signInResult = await this.signInManager.CheckPasswordSignInAsync(user, password, lockoutOnFailure);
            if (!signInResult.Succeeded)
            {
                return null;
            }

            var claims = await this.userManager.GetClaimsAsync(user);
            var jwt = this.jwtGenerator.GenerateAccessToken(user, claims);

            return jwt;
        }

        /// <summary>
        /// Determines whether two-factor-auth is enabled for the specified user.
        /// </summary>
        /// <param name="user">The user.</param>
        /// <returns>
        ///   <c>true</c> if two-factor-auth is enabled for the specified user; otherwise, <c>false</c>.
        /// </returns>
        private async Task<bool> IsTfaEnabledAsync(TUser user) => this.userManager.SupportsUserTwoFactor && await this.userManager.GetTwoFactorEnabledAsync(user) && (await this.userManager.GetValidTwoFactorProvidersAsync(user)).Count > 0;
    }
}
