using LoginWebAPI_RoleBaed_.Context;
using LoginWebAPI_RoleBaed_.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace LoginWebAPI_RoleBaed_.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : Controller
    {
        private readonly AppDbContext _authContext;
        public UserController(AppDbContext appDbContext)
        {
            _authContext = appDbContext ;
        }
        // For login
        [HttpPost("authenticate")]
        public async Task<IActionResult> Authenticate([FromBody] User userObj)
        {
            
            if (userObj == null)
            {
                return BadRequest();
            }

            var user = await _authContext.Users.FirstOrDefaultAsync(x => x.UserName == userObj.UserName && x.Password == userObj.Password);
            if (user == null)
            {
                return NotFound(new { Message = "User Not Found" });
            }

            user.Token = CreateJwt(user);
            return Ok(new
            {
                Token = user.Token,
                Message = "Login Successful"
            });
        }

        //For register
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] User userObj)
        {
            if(userObj == null)
            {
                return BadRequest();
            }
            await _authContext.Users.AddAsync(userObj);
            await _authContext.SaveChangesAsync();
            return Ok(new
            {
                Message = "Registered Successfull"
            });

        }
        private string CreateJwt(User user)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("veryverysecret.....");
          
            var identity = new ClaimsIdentity(new Claim[]
    {
         new Claim(ClaimTypes.Role, user.Role),
                new Claim(ClaimTypes.Name,$"{user.UserName}")
    });

            var credentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = identity,
                Expires = DateTime.Now.AddDays(1),
                SigningCredentials = credentials
            };
            var token = jwtTokenHandler.CreateToken(tokenDescriptor);

            return jwtTokenHandler.WriteToken(token);
        }
        [Authorize]
        [HttpGet]
        public async Task<IActionResult> GetAllUsers()
        {
            return Ok(await _authContext.Users.ToListAsync());
        }

    }
}
