using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using DatingApp.API.Data;
using DatingApp.API.Dtos;
using DatingApp.API.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace DatingApp.API.Controllers
{
    [Route("api/[controller]")]
    public class AuthController: Controller
    {
        public IAuthRepository _repo { get; }
         public Microsoft.Extensions.Configuration.IConfiguration _config { get; }
        public AuthController(IAuthRepository repo, Microsoft.Extensions.Configuration.IConfiguration config)
        {
            _repo = repo;
             _config = config;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody]UserForRegisterDto  userForRegisterDto)
        {

             userForRegisterDto.Username=userForRegisterDto.Username.ToLower();
            // validation request
            if(!ModelState.IsValid)
                return BadRequest(ModelState);

           

            if(await _repo.UserExists(userForRegisterDto.Username))
            ModelState.AddModelError("Username","Username already exists");
            //    return BadRequest("User is already taken.");

            var userToCreate=new User{
                Username=userForRegisterDto.Username
            };
            var createUser=await _repo.Register(userToCreate, userForRegisterDto.Password);
            return StatusCode(201);

        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody]UserForLoginDto userForLoginDto)
        {
            var userFromRepo=await _repo.Login(userForLoginDto.Username, userForLoginDto.Password);

            if(userFromRepo==null)
                return Unauthorized();
            
            var tokenHandler=new JwtSecurityTokenHandler();
            var key=Encoding.ASCII.GetBytes(_config.GetSection("AppSettings:secretkey").Value);
            var tokenDescriptor=new SecurityTokenDescriptor
            {
                Subject=new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.NameIdentifier, userFromRepo.Id.ToString()),
                    new Claim(ClaimTypes.Name,userFromRepo.Username)
                }),
                Expires= System.DateTime.Now.AddDays(1),
                SigningCredentials=new SigningCredentials(new SymmetricSecurityKey(key),SecurityAlgorithms.HmacSha512Signature)
            };

            var token=tokenHandler.CreateToken(tokenDescriptor);
            var tokenString=tokenHandler.WriteToken(token);

            return Ok(new {tokenString});
            
        }

    }
}
