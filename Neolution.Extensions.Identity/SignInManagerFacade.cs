﻿namespace Neolution.Extensions.Identity
{
    using System.Linq.Expressions;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.Extensions.Logging;
    using Neolution.Extensions.Identity.Abstractions;

    /// <summary>
    /// Provides a facade over the SignInManager with additional logging capabilities.
    /// </summary>
    /// <typeparam name="TUser">The type of the user.</typeparam>
    public sealed class SignInManagerFacade<TUser> : ISignInManager<TUser>
        where TUser : IdentityUser<Guid>
    {
        /// <summary>
        /// The logger used for logging operations.
        /// </summary>
        private readonly ILogger<SignInManagerFacade<TUser>> logger;

        /// <summary>
        /// The underlying SignInManager.
        /// </summary>
        private readonly SignInManager<TUser> manager;

        /// <summary>
        /// Initializes a new instance of the <see cref="SignInManagerFacade{TUser}"/> class.
        /// </summary>
        /// <param name="logger">The logger.</param>
        /// <param name="manager">The manager.</param>
        public SignInManagerFacade(ILogger<SignInManagerFacade<TUser>> logger, SignInManager<TUser> manager)
        {
            this.logger = logger;
            this.manager = manager;
        }

        /// <inheritdoc />
        public async Task<SignInResponse> PasswordSignInAsync(TUser user, string password, bool isPersistent, bool lockoutOnFailure)
        {
            var result = await this.manager.PasswordSignInAsync(user, password, isPersistent, lockoutOnFailure);
            this.LogSignInResult(result, $"Signing in user with id={user.Id} using provided password");
            this.TraceLogParameter(isPersistent);
            this.TraceLogParameter(lockoutOnFailure);
            return ConvertToSignInResponse(result);
        }

        /// <inheritdoc />
        public async Task<SignInResponse> ExternalLoginSignInAsync(string loginProvider, string providerKey, bool isPersistent) => await this.ExternalLoginSignInAsync(loginProvider, providerKey, isPersistent, bypassTwoFactor: false);

        /// <inheritdoc />
        public async Task<SignInResponse> ExternalLoginSignInAsync(string loginProvider, string providerKey, bool isPersistent, bool bypassTwoFactor)
        {
            var result = await this.manager.ExternalLoginSignInAsync(loginProvider, providerKey, isPersistent, bypassTwoFactor);
            this.LogSignInResult(result, $"Signing in user via external login with providerKey={providerKey} using loginProvider={loginProvider}");
            this.TraceLogParameter(isPersistent);
            this.TraceLogParameter(bypassTwoFactor);
            return ConvertToSignInResponse(result);
        }

        /// <summary>
        /// Used to ensure that a user is allowed to sign in.
        /// </summary>
        /// <param name="user">The user</param>
        /// <returns>Null if the user should be allowed to sign in, otherwise the SignInResponse why they should be denied.</returns>
        public async Task<SignInResponse?> PreSignInCheckAsync(TUser user)
        {
            this.logger.LogTrace("Check if user meets formal account requirements to sign-in");
            if (!await this.manager.CanSignInAsync(user).ConfigureAwait(false))
            {
                this.logger.LogDebug("User is not allowed to sign-in");
                return ConvertToSignInResponse(SignInResult.NotAllowed);
            }

            if (this.manager.UserManager.SupportsUserLockout)
            {
                this.logger.LogDebug("Lockout is supported - ensure user is not locked out");
                if (await this.manager.UserManager.IsLockedOutAsync(user).ConfigureAwait(false))
                {
                    this.manager.Logger.LogWarning(new EventId(3, "UserLockedOut"), "User is currently locked out.");
                    return ConvertToSignInResponse(SignInResult.LockedOut);
                }
            }

            this.logger.LogTrace("Pre-sign-in check completed with no errors");
            return null;
        }

        /// <summary>
        /// Converts a SignInResult to a SignInResponse.
        /// </summary>
        /// <param name="result">The SignInResult to convert.</param>
        /// <returns>The corresponding SignInResponse.</returns>
        private static SignInResponse ConvertToSignInResponse(SignInResult result)
        {
            if (result.Succeeded)
            {
                return SignInResponse.Success;
            }

            if (result.IsLockedOut)
            {
                return SignInResponse.Lockout;
            }

            if (result.IsNotAllowed)
            {
                return SignInResponse.NotAllowed;
            }

            if (result.RequiresTwoFactor)
            {
                return SignInResponse.TwoFactorRequired;
            }

            return SignInResponse.Failed;
        }

        /// <summary>
        /// Logs the result of a sign-in attempt.
        /// </summary>
        /// <param name="result">The result of the sign-in attempt.</param>
        /// <param name="message">The message to log.</param>
        private void LogSignInResult(SignInResult result, string message)
        {
            if (result.Succeeded)
            {
                this.logger.LogDebug("{message} succeeded", message);
            }
            else
            {
                this.logger.LogWarning("{message} failed", message);
                this.logger.LogDebug("SignInResult: {result}", result);
            }
        }

        /// <summary>
        /// Logs a parameter's name and value at the Trace level.
        /// </summary>
        /// <typeparam name="T">The type of the parameter.</typeparam>
        /// <param name="value">The value of the parameter.</param>
        private void TraceLogParameter<T>(T value)
        {
            if (this.logger.IsEnabled(LogLevel.Trace))
            {
                var paramName = GetVariableName(() => value);
                this.logger.LogTrace("Parameter {Name}: {Value}", paramName, value);
            }

            static string GetVariableName(Expression<Func<T>> expr) => ((MemberExpression)expr.Body).Member.Name;
        }
    }
}
