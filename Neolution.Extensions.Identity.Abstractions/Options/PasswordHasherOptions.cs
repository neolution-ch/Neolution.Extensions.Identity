﻿namespace Neolution.Extensions.Identity.Abstractions.Options
{
    /// <summary>
    /// The password hasher options.
    /// </summary>
    public class PasswordHasherOptions
    {
        /// <summary>
        /// Gets or sets the work factor for the BCrypt password hashing algorithm.
        /// </summary>
        /// <remarks>
        /// Hashing speeds tried out for different devices using different work factors (WF):
        /// DELL XPS13:     900ms -> WF:13
        /// LENOVO T460s:   745ms -> WF:13
        /// LENOVO T460s:  1530ms -> WF:14
        /// </remarks>
        public int BCryptWorkFactor { get; set; } = 13;
    }
}
