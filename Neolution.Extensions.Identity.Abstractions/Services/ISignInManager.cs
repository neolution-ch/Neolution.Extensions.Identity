namespace Neolution.Extensions.Identity.Abstractions.Services
{
    using System.Threading.Tasks;
    using Neolution.Extensions.Identity.Abstractions.Models;

    /// <summary>
    /// Provides the APIs for user sign in.
    /// </summary>
    public interface ISignInManager
    {
        /// <summary>
        /// Attempts a password sign in for a user.
        /// </summary>
        /// <param name="user">The user to sign in.</param>
        /// <param name="password">The password to attempt to sign in with.</param>
        /// <param name="lockoutOnFailure">Flag indicating if the user account should be locked if the sign in fails.</param>
        /// <returns>The task object representing the asynchronous operation containing the <see name="SignInResult"/>
        /// for the sign-in attempt.</returns>
        /// <returns><c>true</c> if login succeeded; otherwise <c>false</c>.</returns>
        Task<bool> CheckPasswordSignInAsync(ApplicationUser user, string password, bool lockoutOnFailure);
    }
}
