using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using InmobiliariaEfler.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;

namespace InmobiliariaEfler.Controllers;

public class HomeController : Controller
{
    private readonly ILogger<HomeController> _logger;
    //private RepositorioUsuario repoUsuario;


    public HomeController(ILogger<HomeController> logger)//,IConfiguration configuration
    {
        _logger = logger;
        //repoUsuario= new RepositorioUsuario(configuration);
    }

    [Authorize]
    public IActionResult Index()
    {
        TempData["Nombre"] = User.Claims.First(x => x.Type == "Fullname").Value;
        return View();
    }

    public IActionResult Restringido()
    {
        return View();
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
}
