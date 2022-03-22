namespace Neolution.Extensions.Identity
{
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Identity;
    using Neolution.Extensions.Identity.Abstractions;
    using Neolution.Extensions.Identity.Abstractions.Models;
    using Neolution.Extensions.Identity.Abstractions.Services;

    /// <inheritdoc />
    public class SignInManagerFacade : ISignInManager
    {
        /// <summary>
        /// The sign in manager.
        /// </summary>
        private readonly SignInManager<ApplicationUser> manager;

        /// <summary>
        /// Initializes a new instance of the <see cref="SignInManagerFacade"/> class.
        /// </summary>
        /// <param name="manager">The manager.</param>
        public SignInManagerFacade(SignInManager<ApplicationUser> manager)
        {
            this.manager = manager;
        }

        /// <inheritdoc />
        public async Task<bool> CheckPasswordSignInAsync(ApplicationUser user, string password, bool lockoutOnFailure)
        {
            var result = await this.manager.CheckPasswordSignInAsync(user, password, lockoutOnFailure).ConfigureAwait(false);
            return result.Succeeded;
        }
    }
}
