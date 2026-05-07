// ClientApp/Program.cs
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(options =>
    {
        // Use cookies for the local session
        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        // Use OIDC for the login challenge
        options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
    })
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
    {
        options.LoginPath = "/Auth/Login";
    })
    .AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
    {
        // The URL of your AuthorizationServer
        options.Authority = builder.Configuration["OAuth2:Issuer"];
        options.ClientId = builder.Configuration["OAuth2:ClientId"];
        options.ClientSecret = builder.Configuration["OAuth2:ClientSecret"];
        options.ResponseType = "code"; // Use Authorization Code Flow
        options.ResponseMode = "query";
        options.CallbackPath = "/auth/callback";
        options.RequireHttpsMetadata = false;

        // Dev-only: callback comes from a cross-site redirect over plain http,
        // so default Secure+SameSite=None cookies would never come back.
        options.NonceCookie.SameSite = Microsoft.AspNetCore.Http.SameSiteMode.Lax;
        options.NonceCookie.SecurePolicy = Microsoft.AspNetCore.Http.CookieSecurePolicy.SameAsRequest;
        options.CorrelationCookie.SameSite = Microsoft.AspNetCore.Http.SameSiteMode.Lax;
        options.CorrelationCookie.SecurePolicy = Microsoft.AspNetCore.Http.CookieSecurePolicy.SameAsRequest;

        options.SaveTokens = true; // Automatically stores access_token in the cookie
        options.GetClaimsFromUserInfoEndpoint = true;

        options.Scope.Clear();
        options.Scope.Add("openid");
        options.Scope.Add("profile");
        options.Scope.Add("offline_access"); // Request refresh tokens
    });

builder.Services.AddAuthorization();
builder.Services.AddControllersWithViews();
builder.Services.AddHttpClient();
builder.Services.AddHttpClient<ClientApp.Services.OAuth2Service>();

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
