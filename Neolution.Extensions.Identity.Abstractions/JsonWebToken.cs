namespace Neolution.Extensions.Identity.Abstractions
{
    using System;

    /// <summary>
    /// The JSON web token.
    /// </summary>
    public class JsonWebToken
    {
        /// <summary>
        /// Gets or sets the date and time the access token expires.
        /// </summary>
        public DateTimeOffset ExpiresDateTime { get; set; }

        /// <summary>
        /// Gets or sets the access token.
        /// </summary>
        public string AccessToken { get; set; } = string.Empty;
    }
}
