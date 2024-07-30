namespace Neolution.Extensions.Identity
{
    using Microsoft.Extensions.Options;
    using Neolution.Extensions.Identity.Abstractions.Options;

    /// <inheritdoc />
    public class NeolutionIdentityOptionsValidator : IValidateOptions<NeolutionIdentityOptions>
    {
        /// <summary>
        /// The minimum allowed work factor
        /// </summary>
        /// <remarks>
        /// Do not allow developers to choose work factors that are too low in our opinion.
        /// FPGAs are scary fast: https://www.cqure.nl/en/knowledge-platform/bcrypt-password-cracking-extremely-slow-not-if-you-are-using-hundreds-of-fpgas
        /// </remarks>
        private const int MinWorkFactor = 12;

        /// <inheritdoc />
        public ValidateOptionsResult Validate(string? name, NeolutionIdentityOptions options)
        {
            if (options.PasswordHasher.BCryptWorkFactor < MinWorkFactor)
            {
                return ValidateOptionsResult.Fail($"For security reasons, BCryptWorkFactor must be at least {MinWorkFactor}.");
            }

            return ValidateOptionsResult.Success;
        }
    }
}
