namespace Neolution.Extensions.Identity.Abstractions.Options
{
    /// <summary>
    /// Neolution Identity Options
    /// </summary>
    public class NeolutionIdentityOptions
    {
        /// <summary>
        /// Gets or sets the Google options.
        /// </summary>
        public GoogleOptions? Google { get; set; }

        /// <summary>
        /// Gets or sets the password hasher options.
        /// </summary>
        public PasswordHasherOptions PasswordHasher { get; set; } = new();
    }
}
