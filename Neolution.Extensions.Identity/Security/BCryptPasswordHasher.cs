namespace Neolution.Extensions.Identity.Security
{
    using System.Diagnostics.CodeAnalysis;
    using Neolution.Abstractions.Security;

    /// <inheritdoc />
    /// <summary>
    /// Uses BCrypt as a password hashing provider
    /// </summary>
    [SuppressMessage("Performance", "CA1812: Avoid uninstantiated internal classes", Justification = "It will be instantiated by dependency injection.")]
    internal class BCryptPasswordHasher : IPasswordHasher
    {
        /// <summary>
        /// The work factor
        /// </summary>
        private readonly int hashingRounds;

        /// <summary>
        /// Initializes a new instance of the <see cref="BCryptPasswordHasher"/> class.
        /// </summary>
        /// <remarks>
        /// Hashing speeds for different devices using different work factors (WF):
        /// DELL XPS13:     900ms -> WF:13
        /// LENOVO T460s:   745ms -> WF:13
        /// LENOVO T460s:  1530ms -> WF:14
        /// </remarks>
        public BCryptPasswordHasher()
        {
            this.hashingRounds = 13;
        }

        /// <inheritdoc />
        public string CreateHash(string plainTextPassword)
        {
            return this.CreateHash(plainTextPassword, this.hashingRounds);
        }

        /// <inheritdoc />
        public string CreateHash(string plainTextPassword, int workFactor)
        {
            return BCrypt.Net.BCrypt.HashPassword(plainTextPassword, workFactor);
        }

        /// <inheritdoc />
        public bool VerifyHash(string hashedPassword, string plainTextPassword)
        {
            return BCrypt.Net.BCrypt.Verify(plainTextPassword, hashedPassword);
        }
    }
}
