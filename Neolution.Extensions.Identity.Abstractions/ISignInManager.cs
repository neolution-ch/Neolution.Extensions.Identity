namespace Neolution.Extensions.Identity.Abstractions
{
    using Microsoft.AspNetCore.Identity;

    /// <summary>
    /// Provides the APIs for user sign in.
    /// </summary>
    /// <typeparam name="TUser">The type encapsulating a user.</typeparam>
    public interface ISignInManager<TUser>
        where TUser : IdentityUser<Guid>
    {
        /// <summary>
        /// Attempts a password sign in for a user.
        /// </summary>
        /// <param name="user">The user to sign in.</param>
        /// <param name="password">The password to attempt to sign in with.</param>
        /// <param name="lockoutOnFailure">Flag indicating if the user account should be locked if the sign in fails.</param>
        /// <returns>The task object representing the asynchronous operation containing the <see name="SignInResult"/>
        /// for the sign-in attempt.</returns>
        /// <returns>The task object representing the asynchronous operation containing the <see name="SignInResponse"/>
        /// for the sign-in attempt.</returns>
        Task<SignInResponse> CheckPasswordSignInAsync(TUser user, string password, bool lockoutOnFailure);

        /// <summary>
        /// Used to ensure that a user is allowed to sign in.
        /// </summary>
        /// <param name="user">The user</param>
        /// <returns>Null if the user should be allowed to sign in, otherwise the SignInResponse why they should be denied.</returns>
        Task<SignInResponse?> PreSignInCheckAsync(TUser user);
    }
}
