using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using ClientApp.Models;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace ClientApp.Controllers;

public class HomeController : Controller
{
    private readonly ILogger<HomeController> _logger;

    public HomeController(ILogger<HomeController> logger)
    {
        _logger = logger;
    }

    [AllowAnonymous]  // Allow unauthenticated access to home page
    public IActionResult Index()
    {
        // Show user info if logged in
        if (User.Identity?.IsAuthenticated == true)
        {
            ViewBag.UserId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            ViewBag.UserName = User.FindFirst(ClaimTypes.Name)?.Value;
            ViewBag.Email = User.FindFirst(ClaimTypes.Email)?.Value;
        }
        return View();
    }

    [Authorize]  // Require authentication for privacy page
    public IActionResult Privacy()
    {
        // Get user information from the claims
        ViewBag.UserId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        ViewBag.UserName = User.FindFirst(ClaimTypes.Name)?.Value;
        ViewBag.Email = User.FindFirst(ClaimTypes.Email)?.Value;
        
        return View();
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    [AllowAnonymous]  // Allow unauthenticated access to error page
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
}