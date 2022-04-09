using JwtAndIdentity.Helpers;
using JwtAndIdentity.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace JwtAndIdentity.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly JWT _jWT;
        public AuthService(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager , IOptions<JWT> jWT)
        {
            _userManager = userManager;
            _jWT = jWT.Value;
            _roleManager = roleManager;
        }

        public async Task<AuthModel> RegisterAsync(RegisterModel model)
        {
            if(await _userManager.FindByEmailAsync(model.Email) is not null)
            {
                return new AuthModel { Message = "Email is already registered!" };
            }

            if (await _userManager.FindByNameAsync(model.Username) is not null)
            {
                return new AuthModel { Message = "Username is already registered!" };
            }

            var user = new ApplicationUser
            {
                UserName = model.Username,
                Email = model.Email,
                FirstName = model.FirstName,
                SecondName = model.SecondName,
            };

            var result = await _userManager.CreateAsync(user,model.Password);
            if (!result.Succeeded) 
            { 
                var errors = string.Empty;
                foreach (var item in result.Errors)
                {
                    errors += $"{item.Description},";
                };
                return new AuthModel { Message = errors };
            }
            await _userManager.AddToRoleAsync(user, "User");
            var JwtSecurityToken = await CreateJwtToken(user);

            return new AuthModel
            {
                ExpiresOn = JwtSecurityToken.ValidTo,
                IsAuthenticated = true,
                Roles = new List<string> { "User"},
                Token = new JwtSecurityTokenHandler().WriteToken(JwtSecurityToken),
                Username = model.Username,
            };
        }

        private async Task<JwtSecurityToken> CreateJwtToken(ApplicationUser user)
        {
            var userClaims = await _userManager.GetClaimsAsync(user);
            var roles = await _userManager.GetRolesAsync(user);
            var roleClaims = new List<Claim>();

            foreach (var role in roles)
                roleClaims.Add(new Claim("roles", role));

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim("uid", user.Id)
            }
            .Union(userClaims)
            .Union(roleClaims);

            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jWT.Key));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

            var jwtSecurityToken = new JwtSecurityToken(
                issuer: _jWT.Issuer,
                audience: _jWT.Audience,
                claims: claims,
                //expires: DateTime.Now.AddDays(_jWT.DurationDays),
                expires: DateTime.Now.AddMinutes(5),
                signingCredentials: signingCredentials);

            return jwtSecurityToken;
        }

        public async Task<AuthModel> GetTokenAsync(TokenRequestModel model)
        {
            var authModel = new AuthModel();
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user is null || !await _userManager.CheckPasswordAsync(user, model.Password))
            {
                authModel.Message = "Email or Password is incorrect";

                return authModel;
            }
            var jwtSecurityToken = await CreateJwtToken(user);
            var rolesList = await _userManager.GetRolesAsync(user);

            authModel.ExpiresOn = jwtSecurityToken.ValidTo;
            authModel.IsAuthenticated = true;
            authModel.Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
            authModel.Username = model.Email;
            authModel.Roles = rolesList.ToList();

            return authModel;
        }

        public async Task<string> AddRoleAsync(AddRoleModel model)
        {
            var user = await _userManager.FindByIdAsync(model.UserId);
            
            if(user is null || !await _roleManager.RoleExistsAsync(model.Role))
            {
                return "Invalid user ID or Role";
            }

            if (await _userManager.IsInRoleAsync(user, model.Role))
            {

                return "user already assigned to this role";
            }

            var result = await _userManager.AddToRoleAsync(user, model.Role);

            return result.Succeeded ? String.Empty : "Something went wrong";
           
        }
    }
}
