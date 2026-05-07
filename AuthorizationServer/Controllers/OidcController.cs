using System.Security.Claims;
using AuthorizationServer.Models;
using AuthorizationServer.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace AuthorizationServer.Controllers
{
    [ApiController]
    public class OidcController : ControllerBase
    {
        private readonly ISigningKeyService _signingKeys;
        private readonly UserManager<ApplicationUser> _userManager;

        public OidcController(ISigningKeyService signingKeys, UserManager<ApplicationUser> userManager)
        {
            _signingKeys = signingKeys;
            _userManager = userManager;
        }

        [HttpGet("/.well-known/openid-configuration")]
        public IActionResult Discovery()
        {
            var issuer = $"{Request.Scheme}://{Request.Host}";

            return Ok(new
            {
                issuer,
                authorization_endpoint = $"{issuer}/oauth/authorize",
                token_endpoint = $"{issuer}/oauth/token",
                userinfo_endpoint = $"{issuer}/connect/userinfo",
                jwks_uri = $"{issuer}/.well-known/jwks.json",
                response_types_supported = new[] { "code" },
                subject_types_supported = new[] { "public" },
                id_token_signing_alg_values_supported = new[] { SecurityAlgorithms.RsaSha256 },
                scopes_supported = new[] { "openid", "profile", "email", "offline_access" },
                grant_types_supported = new[] { "authorization_code", "refresh_token", "password" },
                token_endpoint_auth_methods_supported = new[] { "client_secret_post", "client_secret_basic" },
                claims_supported = new[] { "sub", "name", "preferred_username", "email" }
            });
        }

        [HttpGet("/.well-known/jwks.json")]
        public IActionResult Jwks()
        {
            var jwk = _signingKeys.GetPublicJsonWebKey();
            return Ok(new
            {
                keys = new[]
                {
                    new
                    {
                        kty = jwk.Kty,
                        use = jwk.Use,
                        alg = jwk.Alg,
                        kid = jwk.Kid,
                        n = jwk.N,
                        e = jwk.E
                    }
                }
            });
        }

        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        [HttpGet("/connect/userinfo")]
        [HttpPost("/connect/userinfo")]
        public async Task<IActionResult> UserInfo()
        {
            var sub = User.FindFirstValue("sub") ?? User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(sub))
                return Unauthorized();

            var user = await _userManager.FindByIdAsync(sub);
            if (user == null)
                return Unauthorized();

            return Ok(new
            {
                sub = user.Id,
                name = user.UserName,
                preferred_username = user.UserName,
                email = user.Email,
                email_verified = user.EmailConfirmed
            });
        }
    }
}
