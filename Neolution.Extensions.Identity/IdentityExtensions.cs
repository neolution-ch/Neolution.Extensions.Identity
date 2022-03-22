namespace Microsoft.Extensions.DependencyInjection
{
    using Microsoft.AspNetCore.Identity;
    using Neolution.Abstractions.Security;
    using Neolution.Extensions.Identity;
    using Neolution.Extensions.Identity.Abstractions.Models;
    using Neolution.Extensions.Identity.Abstractions.Services;
    using Neolution.Extensions.Identity.Security;
    using Neolution.Extensions.Identity.Stores;

    /// <summary>
    /// Extension methods for services working with ASP.NET Core Identity.
    /// </summary>
    public static class IdentityExtensions
    {
        /// <summary>
        /// Adds the identity services.
        /// </summary>
        /// <typeparam name="TUser">The type of the user.</typeparam>
        /// <typeparam name="TRole">The type of the role.</typeparam>
        /// <typeparam name="TClaimType">The type of the claim type.</typeparam>
        /// <param name="services">The services.</param>
        public static void AddNeolutionIdentity<TUser, TRole, TClaimType>(this IServiceCollection services)
            where TUser : ApplicationUser
            where TRole : ApplicationRole
            where TClaimType : Enum
        {
            // Use Identity Framework but with a custom User and Role store instead of Entity Framework
            services.AddIdentity<TUser, TRole>()
                .AddUserStore<UserStore<TUser, TClaimType>>()
                .AddRoleStore<RoleStore>()
                .AddDefaultTokenProviders();

            // Register UserManager and SignInManager facades
            services.AddScoped<IUserManager<TUser>, UserManagerFacade<TUser>>();

            // Configure password hashing
            services.AddSingleton<IPasswordHasher, BCryptPasswordHasher>();
            services.AddSingleton<IPasswordHasher<TUser>, IdentityPasswordHasher<TUser>>();
        }
    }
}
