using System;
using System.Threading.Tasks;
using Microsoft.Owin;
using Owin;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.AspNet.Identity;
using Microsoft.Owin.Security.Cookies;

[assembly: OwinStartup(typeof(IdentityWebApplication.Startup))]

namespace IdentityWebApplication
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            string connectionString = @"Data Source=(LocalDb)\MSSQLLocalDB;Initial Catalog=IdentityDB;Integrated Security=True";

            app.CreatePerOwinContext(() => new IdentityDbContext(connectionString));

            app.CreatePerOwinContext<UserStore<IdentityUser>>((opt, cont) => new UserStore<IdentityUser>(cont.Get<IdentityDbContext>()));

            app.CreatePerOwinContext<UserManager<IdentityUser>>((opt, cont) => new UserManager<IdentityUser>(cont.Get<UserStore<IdentityUser>>()));

            app.CreatePerOwinContext<SignInManager<IdentityUser, string>>((opt, cont) => new SignInManager<IdentityUser, string>(cont.Get<UserManager<IdentityUser>>(), cont.Authentication));

            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                LoginPath = new PathString("/Account/Login"),
                Provider = new CookieAuthenticationProvider
                {
                    // Enables the application to validate the security stamp when the user logs in.
                    // This is a security feature which is used when you change a password or add an external login to your account.  
                    OnValidateIdentity = SecurityStampValidator.OnValidateIdentity<UserManager<IdentityUser>, IdentityUser>(
                    validateInterval: TimeSpan.FromMinutes(30),
                    regenerateIdentity: (manager, user) => manager.CreateIdentityAsync(user, DefaultAuthenticationTypes.ApplicationCookie))
                }
            });
        }
    }
}
