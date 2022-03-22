namespace Neolution.Extensions.Identity
{
    using System.Collections.Generic;
    using System.Security.Claims;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.Extensions.Options;
    using Neolution.Extensions.Identity.Abstractions;
    using Neolution.Extensions.Identity.Abstractions.Models;

    /// <inheritdoc />
    public class AdditionalUserClaimsPrincipalFactory : UserClaimsPrincipalFactory<ApplicationUser, ApplicationRole>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AdditionalUserClaimsPrincipalFactory"/> class.
        /// </summary>
        /// <param name="userManager">The user manager.</param>
        /// <param name="roleManager">The role manager.</param>
        /// <param name="optionsAccessor">The options accessor.</param>
        public AdditionalUserClaimsPrincipalFactory(UserManager<ApplicationUser> userManager, RoleManager<ApplicationRole> roleManager, IOptions<IdentityOptions> optionsAccessor)
            : base(userManager, roleManager, optionsAccessor)
        {
        }

        /// <inheritdoc />
        public override async Task<ClaimsPrincipal> CreateAsync(ApplicationUser user)
        {
            var principal = await base.CreateAsync(user).ConfigureAwait(false);

            var identity = principal.Identity as ClaimsIdentity;
            var claims = new List<Claim> { new ("amr", user.MfaEnabled ? "mfa" : "pwd") };
            identity?.AddClaims(claims);

            return principal;
        }
    }
}
