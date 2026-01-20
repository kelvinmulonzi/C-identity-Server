using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using ClientApp.Models;
using Microsoft.Extensions.Configuration;

namespace ClientApp.Services
{
    public class OAuth2Service
    {
        private readonly HttpClient _httpClient;
        private readonly IConfiguration _configuration;

        public OAuth2Service(HttpClient httpClient, IConfiguration configuration)
        {
            _httpClient = httpClient;
            _configuration = configuration;
        }

        public async Task<TokenResponse?> ExchangeCodeForToken(string code, string redirectUri)
        {
            var tokenEndpoint = _configuration["OAuth2:TokenEndpoint"] ?? throw new InvalidOperationException("TokenEndpoint is not configured.");
            var clientId = _configuration["OAuth2:ClientId"] ?? throw new InvalidOperationException("ClientId is not configured.");
            var clientSecret = _configuration["OAuth2:ClientSecret"] ?? throw new InvalidOperationException("ClientSecret is not configured.");

            var tokenRequest = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint)
            {
                Content = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["grant_type"] = "authorization_code",
                    ["code"] = code,
                    ["redirect_uri"] = redirectUri,
                    ["client_id"] = clientId,
                    ["client_secret"] = clientSecret
                })
            };

            var response = await _httpClient.SendAsync(tokenRequest);
            response.EnsureSuccessStatusCode();

            var responseContent = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<TokenResponse>(responseContent, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        }

        public async Task<TokenResponse?> GetTokenWithPasswordAsync(string username, string password)
        {
            var tokenEndpoint = _configuration["OAuth2:TokenEndpoint"] ?? throw new InvalidOperationException("TokenEndpoint is not configured.");
            var clientId = _configuration["OAuth2:ClientId"] ?? throw new InvalidOperationException("ClientId is not configured.");
            var clientSecret = _configuration["OAuth2:ClientSecret"] ?? throw new InvalidOperationException("ClientSecret is not configured.");
            var scope = "read write"; 

            var tokenRequest = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint)
            {
                Content = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["grant_type"] = "password",
                    ["username"] = username,
                    ["password"] = password,
                    ["client_id"] = clientId,
                    ["client_secret"] = clientSecret,
                    ["scope"] = scope
                })
            };

            var response = await _httpClient.SendAsync(tokenRequest);
            if (!response.IsSuccessStatusCode) return null;
            var responseContent = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<TokenResponse>(responseContent, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        }

        public async Task<string> CallProtectedResource(string accessToken, string url)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

            var response = await _httpClient.SendAsync(request);
            response.EnsureSuccessStatusCode();

            return await response.Content.ReadAsStringAsync();
        }
    }
}