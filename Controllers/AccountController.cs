using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNet.Identity.Owin;
using System.Threading.Tasks;
using System.ComponentModel.DataAnnotations;
using Microsoft.Owin.Security;

namespace IdentityWebApplication.Controllers
{
    public class AccountController : Controller
    {
        public UserManager<IdentityUser> UserManager => HttpContext.GetOwinContext().Get<UserManager<IdentityUser>>();
        public SignInManager<IdentityUser, string> SignInManager => HttpContext.GetOwinContext().Get<SignInManager<IdentityUser, string>>();

        private IAuthenticationManager AuthenticationManager
        {
            get
            {
                return HttpContext.GetOwinContext().Authentication;
            }
        }

        // GET: Account
        public ActionResult Index()
        {
            return View();
        }

        public ActionResult Login()
        {
            return View();
        }

        [HttpPost]
        public async Task<ActionResult> Login(LoginModel model)
        {
            if (ModelState.IsValid)
            {
                var signInStatus = await SignInManager.PasswordSignInAsync(model.UserName, model.Password, true, true);

                switch (signInStatus)
                {
                    case SignInStatus.Success:
                        return RedirectToAction("Index", "Home");
                    default:
                        ModelState.AddModelError("error", "Invalid Credentials");
                        break;
                }
            }

            return View(model);
        }

        public ActionResult Logout()
        {
            AuthenticationManager.SignOut();
            return RedirectToAction("Index", "Home");
        }

        public ActionResult Register()
        {
            return View();
        }

        [Authorize]
        public ActionResult Dashboard()
        {
            return View();
        }

        [HttpPost]
        public async Task<ActionResult> Register(RegisterModel model)
        {
            var user = await UserManager.FindByNameAsync(model.UserName);

            if (user != null)
                return RedirectToAction("Index", "Home");

            if (ModelState.IsValid)
            {
                var identityResult = await UserManager.CreateAsync(new IdentityUser(model.UserName), model.Password);

                if (identityResult.Succeeded)
                {
                    return RedirectToAction("Index", "Home");
                }

                ModelState.AddModelError("error", identityResult.Errors.FirstOrDefault());
            }

            return View(model);
        }
    }

    public class RegisterModel
    {
        [Required]
        [EmailAddress]
        [Display(Name = "Email")]
        public string UserName { get; set; }

        [Required]
        [StringLength(100, ErrorMessage = "The {0} must be at least {2} characters long.", MinimumLength = 6)]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public string Password { get; set; }

        [DataType(DataType.Password)]
        [Display(Name = "Confirm password")]
        [System.ComponentModel.DataAnnotations.Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
        public string ConfirmPassword { get; set; }
    }

    public class LoginModel
    {
        [Required]
        public string UserName { get; set; }
        [Required]
        public string Password { get; set; }
    }
}