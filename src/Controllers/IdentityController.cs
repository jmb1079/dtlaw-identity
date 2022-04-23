using Microsoft.AspNetCore.Mvc;
using Dtlaw.Identity.Data;
using Microsoft.AspNetCore.Authorization;
using Dtlaw.Identity.Model;
using Microsoft.AspNetCore.Identity;
using SendGrid;
using Microsoft.AspNetCore.Authentication;
using SendGrid.Helpers.Mail;
using System.Text.Encodings.Web;
using System.Security.Claims;

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
        private readonly IConfiguration _configuration;

        public IdentityController(IdentityContext context,
            IUserStore<IdentityUser> userStore,
            IUserEmailStore<IdentityUser> emailStore,
            UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager,
            SignInManager<IdentityUser> signInManager,
            ISendGridClient emailSender,
            ILogger<IdentityController> logger,
            IConfiguration configuration)
        {
            _context = context;
            _userStore = userStore;
            _emailStore = emailStore;
            _userManager = userManager;
            _roleManager = roleManager;
            _signInManager = signInManager;
            _emailSender = emailSender;
            _logger = logger;
            _configuration = configuration;
        }

        //public IList<AuthenticationScheme> ExternalLogins { get; set; }
        //public string ReturnUrl { get; set; }

        [AllowAnonymous]
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegistrationDto registrationDto )
        {
            var returnUrl = Url.Content("~/");
            //ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();
            var user = CreateUser();
            await _userStore.SetUserNameAsync(user, registrationDto.Email, CancellationToken.None);
            await _emailStore.SetEmailAsync(user, registrationDto.Email, CancellationToken.None);
            var result = await _userManager.CreateAsync(user, registrationDto.Password);
            if (result.Succeeded)
            {
                _logger.LogInformation("User " + registrationDto.Email + "created a new account with password.");
                AddUserClaims(user, registrationDto);
                AddUserToRole(user, registrationDto.Organization);
                SendRegistrationEmail(user, returnUrl);
                if (_userManager.Options.SignIn.RequireConfirmedAccount)
                {
                    return Problem(
                        title: "Registration not confirmed",
                        statusCode: 403,
                        detail: "The user started the registration process, but has not confirmed the email registered (" + registrationDto.Email + "). The user must click the link in the 'DTLAW email confirmation' email to complete the registration process."
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

        private async void AddUserClaims(IdentityUser user, RegistrationDto registrationDto)
        {
            List<Claim> newClaims = new List<Claim>();
            if (!String.IsNullOrEmpty(registrationDto.FirstName)){newClaims.Add(new Claim(ClaimTypes.GivenName, registrationDto.FirstName));}
            if (!String.IsNullOrEmpty(registrationDto.LastName)){newClaims.Add(new Claim(ClaimTypes.Surname, registrationDto.LastName));}
            if (registrationDto.DateOfBirth.HasValue){newClaims.Add(new Claim(ClaimTypes.DateOfBirth, registrationDto.DateOfBirth.Value.ToShortDateString()));}
            if (!String.IsNullOrEmpty(registrationDto.MobilePhone)){newClaims.Add(new Claim(ClaimTypes.MobilePhone, registrationDto.MobilePhone));}
            var result = await _userManager.AddClaimsAsync(user, newClaims);
            if (result.Succeeded)
            {
                _logger.LogInformation(String.Format("Claims added for user '{0}'", user.Email));
            }
            else
            {
                _logger.LogCritical(String.Format("Failed to add claims for user '{0}'", user.Email));
                _logger.LogCritical(result.Errors.ToString());
            }
        }

        private async void AddUserToRole(IdentityUser user, string organization)
        {
            IdentityRole role = await _roleManager.FindByIdAsync(organization);
            var result = await _userManager.AddToRoleAsync(user, role.NormalizedName);
            if (result.Succeeded)
            {
                _logger.LogInformation(String.Format("User '{0}' added to role '{1}'", user.Email, role.Name));
            }
            else
            {
                _logger.LogCritical(String.Format("User '{0}' failed to get added to role '{1}'", user.Email, role.Name));
                _logger.LogCritical(result.ToString());
            }
        }

        private async void SendRegistrationEmail(IdentityUser user, string returnUrl)
        {
            var userId = await _userManager.GetUserIdAsync(user);
            var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var callbackUrl = Url.Page(
                "/Account/ConfirmEmail",
                pageHandler: null,
                values: new { area = "Identity", userId = userId, code = code, returnUrl = returnUrl },
                protocol: Request.Scheme);
            var content = $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.";
            var message = MailHelper.CreateSingleEmail(
                new EmailAddress(_configuration.GetValue<string>("SendGrid.FromAddress")),
                new EmailAddress(user.Email),
                _configuration.GetValue<string>("SendGrid.Subject"),
                content,
                content);
            var response = await _emailSender.SendEmailAsync(message);
            _logger.LogInformation(response.IsSuccessStatusCode
                           ? $"Email to {user.Email} queued successfully!"
                           : $"Failed to send email to {user.Email}");
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