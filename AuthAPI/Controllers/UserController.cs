using AuthAPI.Context;
using AuthAPI.Helpers;
using AuthAPI.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Text;
using System.Text.RegularExpressions;

namespace AuthAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly AppDbContext _authContext;
        public UserController(AppDbContext appDbContext) 
        {
            _authContext = appDbContext;
        }

        [HttpPost("authenticate")]
        public async Task<IActionResult> Authenticate([FromBody] User userObj)
        {
            if (userObj == null)
                return BadRequest();
            
            var user = await _authContext.Users.FirstOrDefaultAsync(x => x.Username == userObj.Username);
            if (user == null)
                return NotFound(new { Message = "User Not Found!" });

            if (!PasswordHasher.VerifyPassword(userObj.Password, user.Password))
                return BadRequest(new { Message = "Password is Incorrect!" });

            return Ok(new
            {
                Message = "Login Successful!"
            });
        }

        [HttpPost("register")]
        public async Task<IActionResult> RegisterUser([FromBody] User userObj)
        {
            if (userObj == null)
                return BadRequest();

            if (await CheckUserNameExistsAsync(userObj.Username))
                return BadRequest(new { Message = "Username already exists!" });

            if (await CheckEmailExistsAsync(userObj.Email))
                return BadRequest(new { Message = "Email already exists!" });

            var pass = CheckPasswordStrenth(userObj.Password);
            if (!string.IsNullOrWhiteSpace(pass))
                return BadRequest(new { Message = pass.ToString() });

            userObj.Password = PasswordHasher.HashPassword(userObj.Password);
            userObj.Role = "User";
            userObj.Token = string.Empty;

            await _authContext.Users.AddAsync(userObj);
            await _authContext.SaveChangesAsync();

            return Ok(new
            {
                Message = "User Registered!"
            });
        }

        private Task<bool> CheckUserNameExistsAsync(string userName)
            => _authContext.Users.AnyAsync(x => x.Username == userName);

        private Task<bool> CheckEmailExistsAsync(string email)
            => _authContext.Users.AnyAsync(x => x.Email == email);

        private string CheckPasswordStrenth(string password)
        {
            StringBuilder sb = new StringBuilder();
            if (password.Length < 5)
                sb.Append("Minimum password length should be 5" + Environment.NewLine);
            if (!(Regex.IsMatch(password, "[a-z]") && Regex.IsMatch(password, "[A-Z]")
                && Regex.IsMatch(password, "[0-9]")))
                sb.Append("Password should be alphanumeric" + Environment.NewLine);
            if (!Regex.IsMatch(password, "[<,>,@,!,#,$,%,^,&,*,(,),_,+,\\[,\\],{,},?,:,;,|,~,`,-,=]"))
                sb.Append("Password should contain special characters" + Environment.NewLine);

            return sb.ToString();
        }
    }
}
