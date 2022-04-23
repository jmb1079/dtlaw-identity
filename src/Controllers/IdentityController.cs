using Microsoft.AspNetCore.Mvc;
using Dtlaw.Identity.Data;
using Microsoft.AspNetCore.Authorization;
using Dtlaw.Identity.Model;
using Microsoft.AspNetCore.Identity;
using SendGrid;
using Microsoft.AspNetCore.Authentication;
using SendGrid.Helpers.Mail;
using System.Text.Encodings.Web;

namespace Dtlaw.Identity.Controllers
{
    [Route("api/[controller]")]
    public class IdentityController : ControllerBase
    {
        private readonly IdentityContext _context;
        private readonly IUserStore<IdentityUser> _userStore;
        private readonly IUserEmailStore<IdentityUser> _emailStore;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly ISendGridClient _emailSender;
        private readonly ILogger<IdentityController> _logger;

        public IdentityController(IdentityContext context,
            IUserStore<IdentityUser> userStore,
            IUserEmailStore<IdentityUser> emailStore,
            UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager,
            SignInManager<IdentityUser> signInManager,
            ISendGridClient emailSender,
            ILogger<IdentityController> logger)
        {
            _context = context;
            _userStore = userStore;
            _emailStore = emailStore;
            _userManager = userManager;
            _roleManager = roleManager;
            _signInManager = signInManager;
            _emailSender = emailSender;
            _logger = logger;
        }

        //public IList<AuthenticationScheme> ExternalLogins { get; set; }
        //public string ReturnUrl { get; set; }

        [AllowAnonymous]
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] UserDto userDto )
        {
            var returnUrl = Url.Content("~/");
            //ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();
            var user = CreateUser();
            await _userStore.SetUserNameAsync(user, userDto.Email, CancellationToken.None);
            await _emailStore.SetEmailAsync(user, userDto.Email, CancellationToken.None);
            var result = await _userManager.CreateAsync(user, userDto.Password);
            if (result.Succeeded)
            {
                _logger.LogInformation("User " + userDto.Email + "created a new account with password.");
                IdentityRole role = await _roleManager.FindByIdAsync(userDto.Organization);
                result = await _userManager.AddToRoleAsync(user, role.NormalizedName);
                var userId = await _userManager.GetUserIdAsync(user);
                var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                var callbackUrl = Url.Page(
                    "/Account/ConfirmEmail",
                    pageHandler: null,
                    values: new { area = "Identity", userId = userId, code = code, returnUrl = returnUrl },
                    protocol: Request.Scheme);
                var message = new SendGridMessage()
                {
                    From = new EmailAddress(userDto.Email),
                    Subject = "DTLAW eamil confirmation",
                    HtmlContent = $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>."
                };
                await _emailSender.SendEmailAsync(message);
                if (_userManager.Options.SignIn.RequireConfirmedAccount)
                {
                    return Problem(
                        title: "Registration not confirmed",
                        statusCode: 403,
                        detail: "The user started the registration process, but has not confirmed the email registered (" + userDto.Email + "). The user must click the link in the 'DTLAW email confirmation' email to complete the registration process."
                    );
                }
                else
                {
                    await _signInManager.SignInAsync(user, isPersistent: false);
                    return Redirect(returnUrl);
                }
            }
            return Problem(statusCode:503);
        }

        private IdentityUser CreateUser()
        {
            try
            {
                return Activator.CreateInstance<IdentityUser>();
            }
            catch
            {
                throw new InvalidOperationException($"Can't create an instance of '{nameof(IdentityUser)}'. " +
                    $"Ensure that '{nameof(IdentityUser)}' is not an abstract class and has a parameterless constructor, or alternatively " +
                    $"override the register page in /Areas/Identity/Pages/Account/Register.cshtml");
            }
        }
    }
}