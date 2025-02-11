namespace Neolution.Extensions.Identity.Abstractions.OpenIdConnect
{
    /// <summary>
    /// OpenID Connect token validation options.
    /// </summary>
    public class OpenIdConnectTokenValidationOptions
    {
        /// <summary>
        /// Gets or sets the client identifier.
        /// </summary>
        public required string ClientId { get; set; }

        /// <summary>
        /// Gets or sets the discovery document URL.
        /// </summary>
        public required string DiscoveryDocumentUrl { get; set; }

        /// <summary>
        /// Gets or sets the issuer.
        /// </summary>
        public required string Issuer { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether to validate the issuer.
        /// </summary>
        public bool ValidateIssuer { get; set; } = true;
    }
}
