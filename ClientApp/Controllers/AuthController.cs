using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace ClientApp.Controllers
{
   
        // We no longer need OAuth2Service or IConfiguration here because 
        // the OIDC middleware handles the API interactions.

        public class AuthController : Controller
        {
            [HttpGet]
            public IActionResult Login()
            {
                // Triggers the OIDC middleware to redirect to the AuthorizationServer's Login page
                return Challenge(new AuthenticationProperties 
                { 
                    RedirectUri = Url.Action("Index", "Home") 
                }, OpenIdConnectDefaults.AuthenticationScheme);
            }

            [HttpGet]
            public IActionResult Register()
            {
                // Redirects to the AuthorizationServer's Register page
                var props = new AuthenticationProperties { RedirectUri = "/" };
                props.Items["prompt"] = "create"; // Custom hint for the server to show Register UI
                return Challenge(props, OpenIdConnectDefaults.AuthenticationScheme);
            }

            [HttpGet]
            public IActionResult Logout()
            {
                // This will clear the local cookie and trigger a redirection to the
                // Authorization Server to end the session there.
                return SignOut(CookieAuthenticationDefaults.AuthenticationScheme, 
                               OpenIdConnectDefaults.AuthenticationScheme);
            }
        }

        
    }
