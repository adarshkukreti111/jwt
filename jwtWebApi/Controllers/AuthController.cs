using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace jwtWebApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static User user=  new User();

        private readonly  IConfiguration _configuration;

        public AuthController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserDto request) 
        {
            CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalts);
            user.Username = request.UserName;
            user.PasswordHash = passwordHash;
            user.PasswordSalts = passwordSalts;

            return Ok(user);
        }

        [HttpPost("login")]
        public async Task<ActionResult<string>> Login(UserDto request)
        {
            if (user.Username != request.UserName)
            {
                return BadRequest("User not found");
            }
            if (!VerifyPasswordHash(request.Password, user.PasswordHash, user.PasswordSalts)) 
            {
                return BadRequest("Wrong Password.!");
            }
            string token = CreateToken(user);
            return Ok(token);
        }
        private string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Username)
            };
            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(
                _configuration.GetSection("AppSettings:Token").Value));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);
            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(30),
                signingCredentials: creds
                );
          
            var jwt = new JwtSecurityTokenHandler().WriteToken(token);
            return jwt;
        }



        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalts) 
        {
            using (var hmac = new HMACSHA512())
            {
                passwordSalts = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

        private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalts)
        {

            using (var hmac = new HMACSHA512(passwordSalts))
            {
                var computeHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return computeHash.SequenceEqual(passwordHash);
            }


        }

    }
}
