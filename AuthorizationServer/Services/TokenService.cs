using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using AuthorizationServer.Models;

namespace AuthorizationServer.Services
{
    public interface ITokenService
    {
        string GenerateAccessToken(string userId, string username, string email, string clientId, string scope);
        string GenerateIdToken(string userId, string username, string email, string clientId, string? nonce);
        string GenerateRefreshToken();
        ClaimsPrincipal ValidateToken(string token);
    }


    public class TokenService : ITokenService
    {
        private readonly IConfiguration _configuration;
        private readonly ISigningKeyService _signingKeys;

        public TokenService(IConfiguration configuration, ISigningKeyService signingKeys)
        {
            _configuration = configuration;
            _signingKeys = signingKeys;
        }

        public string GenerateAccessToken(string userId, string username, string email, string clientId, string scope)
        {
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, userId),
                new Claim("client_id", clientId),
                new Claim("scope", scope),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
                new Claim("username", username),
                new Claim(JwtRegisteredClaimNames.Email, email),
            };

            var expires = DateTime.UtcNow.AddMinutes(int.Parse(_configuration["Jwt:AccessTokenExpirationMinutes"]!));
            return WriteJwt(_configuration["Jwt:Issuer"]!, _configuration["Jwt:Audience"]!, claims, expires);
        }

        public string GenerateIdToken(string userId, string username, string email, string clientId, string? nonce)
        {
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, userId),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
                new Claim("name", username),
                new Claim("preferred_username", username),
                new Claim(JwtRegisteredClaimNames.Email, email),
            };

            if (!string.IsNullOrEmpty(nonce))
                claims.Add(new Claim("nonce", nonce));

            // For ID tokens, audience is the client_id per OIDC spec
            var expires = DateTime.UtcNow.AddMinutes(int.Parse(_configuration["Jwt:AccessTokenExpirationMinutes"]!));
            return WriteJwt(_configuration["Jwt:Issuer"]!, clientId, claims, expires);
        }

        public string GenerateRefreshToken()
        {
            var bytes = new byte[32];
            RandomNumberGenerator.Fill(bytes);
            return Base64UrlEncoder.Encode(bytes);
        }

        public ClaimsPrincipal ValidateToken(string token)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = _signingKeys.GetSecurityKey(),
                ValidateIssuer = true,
                ValidIssuer = _configuration["Jwt:Issuer"],
                ValidateAudience = true,
                ValidAudience = _configuration["Jwt:Audience"],
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            };

            return tokenHandler.ValidateToken(token, validationParameters, out _);
        }

        private string WriteJwt(string issuer, string audience, IEnumerable<Claim> claims, DateTime expires)
        {
            var credentials = new SigningCredentials(_signingKeys.GetSecurityKey(), SecurityAlgorithms.RsaSha256);
            var token = new JwtSecurityToken(
                issuer: issuer,
                audience: audience,
                claims: claims,
                notBefore: DateTime.UtcNow,
                expires: expires,
                signingCredentials: credentials);
            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
