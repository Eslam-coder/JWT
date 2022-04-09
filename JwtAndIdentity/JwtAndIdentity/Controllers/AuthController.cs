using JwtAndIdentity.Models;
using JwtAndIdentity.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;

namespace JwtAndIdentity.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;
        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }

        [HttpPost]
        //public async Task<IActionResult> Login(string returnUrl)
        //{
        //    return 
        //}

        [HttpPost("register")]
        public async Task<IActionResult> RegisterAsync([FromBody] RegisterModel model)
        {
            if(!ModelState.IsValid)
            return BadRequest(ModelState);

            var result = await _authService.RegisterAsync(model);

            //فى حاله ال email موجود اصلا 
            if(result.IsAuthenticated == false)
            {
                return BadRequest(result.Message);
            }

            return Ok(result);
        }

        [HttpPost("Login")]
        public async Task<IActionResult> GetTokenAsync([FromBody] TokenRequestModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var result = await _authService.GetTokenAsync(model);

            //فى حاله ال email موجود اصلا 
            if (result.IsAuthenticated == false)
            {
                return BadRequest(result.Message);
            }

            return Ok(result);
        }

        //[Authorize (Roles ="Admin")]
        [Authorize]
        [HttpPost("addRole")]
        protected async Task<IActionResult> AddRoleAsync([FromBody] AddRoleModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var result = await _authService.AddRoleAsync(model);

            if (!string.IsNullOrEmpty(result))
            {
                return BadRequest(result);
            }

            return Ok(model);
        }
    }
}
