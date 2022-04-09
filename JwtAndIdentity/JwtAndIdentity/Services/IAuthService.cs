using JwtAndIdentity.Models;
using System.Threading.Tasks;

namespace JwtAndIdentity.Services
{
    public interface IAuthService
    {
        Task<AuthModel> RegisterAsync(RegisterModel model);
        Task<AuthModel> GetTokenAsync(TokenRequestModel model);
        Task<string> AddRoleAsync(AddRoleModel model);

    }
}
