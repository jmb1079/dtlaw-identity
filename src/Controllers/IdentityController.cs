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
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;

namespace Dtlaw.Identity.Controllers
{
    [Route("api/[controller]")]
    public class IdentityController : ControllerBase
    {
        private readonly IdentityContext _context;
        private readonly IUserStore<IdentityUser> _userStore;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly ISendGridClient _emailSender;
        private readonly ILogger<IdentityController> _logger;
        private readonly IConfiguration _configuration;

        public IdentityController(IdentityContext context,
            IUserStore<IdentityUser> userStore,
            UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager,
            SignInManager<IdentityUser> signInManager,
            ISendGridClient emailSender,
            ILogger<IdentityController> logger,
            IConfiguration configuration)
        {
            _context = context;
            _userStore = userStore;
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
        public async Task<IActionResult> Register([FromBody] RegistrationDto registrationDto, [FromBody]string? returnUrl = null )
        {
            returnUrl ??= Url.Content("~/");
            //ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();
            var user = CreateUser();
            await _userStore.SetUserNameAsync(user, registrationDto.Email, CancellationToken.None);
            await _userManager.SetEmailAsync(user, registrationDto.Email);
            var result = await _userManager.CreateAsync(user, registrationDto.Password);
            if (result.Succeeded)
            {
                _logger.LogInformation("Created a new account with password for '" + registrationDto.Email + "'.");
                await AddUserClaims(user, registrationDto);
                await AddUserToRole(user, registrationDto.Organization);
                await SendRegistrationEmail(user, returnUrl);
                if ( _userManager.Options.SignIn.RequireConfirmedAccount)
                {
                    //Finished initial process correctly and needs client to confirm by email;
                    return Ok();
                }
                else
                {
                    await _signInManager.SignInAsync(user, isPersistent: false);
                    return Redirect(returnUrl);
                }
            }
            return Problem(statusCode:503);
        }

        [AllowAnonymous]
        [HttpPost("authenticate")]
        public async Task<IActionResult> Authenticate([FromBody]LoginDto loginDto)
        {
            var result = await _signInManager.PasswordSignInAsync(loginDto.Email, loginDto.Password, loginDto.RememberMe, lockoutOnFailure: false);
            if(result.Succeeded)
            {
                _logger.LogInformation(String.Format("User '{0}' logged in", loginDto.Email));
                var user = await _userManager.FindByNameAsync(loginDto.Email);
                string token = await GenerateToken(user.Id);

                return Ok( new
                {
                    Username = loginDto.Email,
                    Token = token
                });
            }
            if(result.RequiresTwoFactor)
            {
                _logger.LogError(String.Format("Multifactor Authentication attempted for login '{0}'. This feature is not implemented", loginDto.Email));
                return Problem(statusCode: 501, title: "MFA not supported");
            }
            if(result.IsLockedOut)
            {
                string errorDetail = String.Format("User account '{0}' is locked. Contact an administrator to unlock the account");
                _logger.LogInformation(errorDetail);
                return Problem( statusCode: 403, title: "Account locked", detail: errorDetail);
            }
            else
            {
                string errorDetail = String.Format("Invalid login attempt for '{0}'", loginDto.Email);
                _logger.LogWarning(errorDetail);
                return Problem( statusCode: 401, title: "Login failed", detail: errorDetail);
            }
        }

        [AllowAnonymous]
        [HttpGet("ConfirmEmail")]
        public async Task<IActionResult> ConfirmEmail(string token, string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user is null)
            {
                string errorDetail = String.Format("Could not find user with id '{0}'", userId);
                _logger.LogError(errorDetail);
                return Problem(statusCode: 404, title: "User not found", detail: errorDetail);
            }
            
            var result = await _userManager.ConfirmEmailAsync(user, token);
            if (result.Succeeded)
            {
                _logger.LogInformation(String.Format("Email confirmation received for '{0}'", user.Email));
                return Ok();
            }
            else
            {
                string errorDetail = String.Format("Attempt to confirm '{0}' has failed", user.Email);
                _logger.LogError(errorDetail);
                return Problem(statusCode: 401, title: "Confirmation failed", detail: errorDetail);
            }
        }

        [HttpPost("logout")]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            _logger.LogInformation(String.Format("User '' logged out"));
            return Ok();
        }

        private async Task<bool> AddUserClaims(IdentityUser user, RegistrationDto registrationDto)
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
                return true;
            }
            else
            {
                _logger.LogCritical(String.Format("Failed to add claims for user '{0}'", user.Email));
                _logger.LogCritical(result.Errors.ToString());
                return false;
            }
        }

        private async Task<bool> AddUserToRole(IdentityUser user, string organization)
        {
            Console.WriteLine(organization);
            IdentityRole role = await _roleManager.FindByIdAsync(organization);
            Console.WriteLine(role.Name);
            var result = await _userManager.AddToRoleAsync(user, role.NormalizedName);
            if (result.Succeeded)
            {
                _logger.LogInformation(String.Format("User '{0}' added to role '{1}'", user.Email, role.Name));
                return true;
            }
            else
            {
                _logger.LogCritical(String.Format("User '{0}' failed to get added to role '{1}'", user.Email, role.Name));
                _logger.LogCritical(result.ToString());
                return false;
            }
        }

        private async Task<bool> SendRegistrationEmail(IdentityUser user, string returnUrl)
        {
            var userId = await _userManager.GetUserIdAsync(user);
            var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var callbackUrl = Url.Page(
                "/Identity/ConfirmEmail",
                pageHandler: null,
                values: new { area = "Identity", userId = userId, code = code, returnUrl = returnUrl },
                protocol: Request.Scheme);
            var content = $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.";
            var message = MailHelper.CreateSingleEmail(
                new EmailAddress(_configuration.GetValue<string>("SendGrid:FromAddress")),
                new EmailAddress(user.Email),
                _configuration.GetValue<string>("SendGrid:Subject"),
                content,
                content);
            var response = await _emailSender.SendEmailAsync(message);
            if(response.IsSuccessStatusCode)
            {
                _logger.LogInformation($"Email to {user.Email} queued successfully!");
                return true;
            }
            else
            {
                _logger.LogWarning($"Failed to send email to {user.Email}");
                return false;
            }
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

        private async Task<string> GenerateToken(string userId)
        {
            byte[] key = System.Text.Encoding.Unicode.GetBytes("PennStateIst440WTeam2!@#$");
            SymmetricSecurityKey securityKey = new SymmetricSecurityKey(key);
            string issuer = "https://dtlaw-identity.azurewebsites.net";
            string audience = "https://dtlawapi.azurewebsites.net";
            var tokenHandler = new JwtSecurityTokenHandler();
            var claims = await _userManager.GetClaimsAsync(await _userManager.FindByIdAsync(userId));
            claims.Add(new Claim(ClaimTypes.NameIdentifier, userId));
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.NameIdentifier, userId),
                }),
                Expires = DateTime.UtcNow.AddMinutes(30),
                Issuer = issuer,
                Audience = audience,
                SigningCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha512Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
    }
}