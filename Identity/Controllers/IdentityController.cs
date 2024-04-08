using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Identity.Persistence.Models.DbModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace Identity.Controllers;
[ApiController]
[Route("api/[controller]/[action]")]
public class IdentityController : Controller
{
    private readonly string _tokenSecret;
    private readonly TimeSpan _tokenLifeTime;
    private readonly string _issuer;
    private readonly string _audience;
    private readonly UserManager<User> _userManager;
    private readonly SignInManager<User> _signInManager;
    

    public IdentityController(IConfiguration configuration, 
        UserManager<User> userManager, SignInManager<User> signInManager)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _tokenSecret = configuration["JwtSettings:Key"]!;
        _tokenLifeTime = TimeSpan.FromHours(Convert.ToInt32(configuration["JwtSettings:TokenLifeTimeHours"]!));
        _issuer = configuration["JwtSettings:Issuer"]!;
        _audience = configuration["JwtSettings:Audience"]!;
    }
    

    //TODO убрать отсюда
    private string GetToken(string userId, string email)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.UTF8.GetBytes(_tokenSecret);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new(JwtRegisteredClaimNames.Sub, email),
            new(JwtRegisteredClaimNames.Email, email),
            //TODO:юзер id
            new("userId", userId)
        };
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.Now.Add(_tokenLifeTime),
            Issuer = _issuer,
            Audience = _audience,
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        };
        var token = tokenHandler.CreateToken(tokenDescriptor);
        var jwt = tokenHandler.WriteToken(token);
        return jwt;
    }

    [HttpPost]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        
        if (ModelState.IsValid)
        {
            var user = new User { Email = request.Email, UserName = request.Email };
            var result = await _userManager.CreateAsync(user, request.Password);
            if (result.Succeeded)
            {
                var jwt = GetToken(user.Id, user.Email);
                return Ok(jwt);
            }
            else
            {
                var message = new StringBuilder();
                foreach (var error in result.Errors)
                {
                    message.Append(error.Description + ". ");
                }

                return BadRequest(message.ToString());
            }
        }
        else
        {
            return BadRequest("Invalid model state");
        }
    }
    [HttpPost]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
            var result = await _signInManager.PasswordSignInAsync(request.Email, request.Password, false, false);
            if (result.Succeeded)
            {
                var user = _userManager.Users.SingleOrDefault(u => u.Email == request.Email);
                return Ok(GetToken(user!.Id, user!.Email!));
            }
            else
            {
                return BadRequest("Invalid email or password");
            }
    }
}