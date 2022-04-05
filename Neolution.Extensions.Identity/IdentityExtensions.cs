namespace Microsoft.Extensions.DependencyInjection
{
    using System.IdentityModel.Tokens.Jwt;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.EntityFrameworkCore;
    using Neolution.Extensions.Identity;
    using Neolution.Extensions.Identity.Abstractions;

    /// <summary>
    /// Extension methods for services working with ASP.NET Core Identity.
    /// </summary>
    public static class IdentityExtensions
    {
        /// <summary>
        /// Adds the identity services.
        /// </summary>
        /// <param name="services">The services.</param>
        public static void AddNeolutionIdentity<TDbContext, TUserAccount>(this IServiceCollection services)
            where TDbContext : DbContext
            where TUserAccount : IdentityUser<Guid>
        {
            services.AddIdentityCore<TUserAccount>(options =>
                {
                    options.SignIn.RequireConfirmedAccount = false;
                })
                .AddEntityFrameworkStores<TDbContext>();

            services.Configure<IdentityOptions>(options =>
            {
                options.User.RequireUniqueEmail = true;
            });
            
            services.AddSingleton<IPasswordHasher<TUserAccount>, IdentityPasswordHasher<TUserAccount>>();
            services.AddScoped<IUserManager<TUserAccount>, UserManagerFacade<TUserAccount>>();

            // By default, Microsoft has some legacy claim mapping that converts
            // standard JWT claims into proprietary ones. This removes those mappings.
            // https://github.com/aspnet/Security/issues/1043
            // https://github.com/dotnet/aspnetcore/issues/4660
            // https://mderriey.com/2019/06/23/where-are-my-jwt-claims/
            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();
            JwtSecurityTokenHandler.DefaultOutboundClaimTypeMap.Clear();
        }
    }
}
