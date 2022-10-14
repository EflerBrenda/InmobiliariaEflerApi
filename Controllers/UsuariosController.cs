using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using InmobiliariaEfler.Models;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace InmobiliariaEfler.Controllers
{
    public class UsuariosController : Controller
    {
        private RepositorioUsuario repoUsuario;
        private readonly IWebHostEnvironment environment;
        private readonly IConfiguration configuration;
        public UsuariosController(IConfiguration configuration, IWebHostEnvironment environment)
        {
            repoUsuario = new RepositorioUsuario(configuration);
            this.environment = environment;
            this.configuration = configuration;
        }
        // GET: Usuarios
        [Authorize(Policy = "Administrador")]
        public ActionResult Index()
        {
            var usuarios = repoUsuario.ObtenerUsuarios();
            return View(usuarios);
        }
        // GET Usuarios/Login
        [AllowAnonymous]
        public ActionResult Login()
        {
            return View();
        }

        // POST: Usuarios/Login
        [HttpPost]
        [ValidateAntiForgeryToken]
        [AllowAnonymous]
        //[ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(UsuarioLogin usuario)
        {
            try
            {
                var returnUrl = String.IsNullOrEmpty(TempData["returnUrl"] as string) ? "/Home" : TempData["returnUrl"].ToString();
                if (ModelState.IsValid)
                {
                    string hashed = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                        password: usuario.Password,
                        salt: System.Text.Encoding.ASCII.GetBytes(configuration["Salt"]),
                        prf: KeyDerivationPrf.HMACSHA1,
                        iterationCount: 1000,
                        numBytesRequested: 256 / 8));

                    var u = repoUsuario.ObtenerPorEmail(usuario.Email);

                    if (u == null || u.Password != hashed)
                    {
                        ModelState.AddModelError("", "El Email o password no son correctos");
                        TempData["returnUrl"] = returnUrl;
                        return View();
                    }
                    var RolNombre = u.RolNombre;
                    var claims = new List<Claim>
                    {
                        new Claim(ClaimTypes.Name, u.Id+""),
                        new Claim("Fullname", u.Nombre + " " + u.Apellido),
                        new Claim(ClaimTypes.Role, RolNombre),
                    };
                    var claimsIdentity = new ClaimsIdentity(
                        claims, CookieAuthenticationDefaults.AuthenticationScheme);


                    await HttpContext.SignInAsync(
                        CookieAuthenticationDefaults.AuthenticationScheme,
                        new ClaimsPrincipal(claimsIdentity));
                    TempData.Remove("returnUrl");
                    return Redirect(returnUrl);
                }
                TempData["returnUrl"] = returnUrl;
                return View();
            }
            catch (Exception e)
            {
                throw;
            }
        }

        [Route("salir", Name = "logout")]
        public async Task<ActionResult> Logout()
        {
            await HttpContext.SignOutAsync(
                CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToAction("Login", "Usuarios");
        }

        // GET: Usuarios/Details/5
        [Authorize]
        public ActionResult Details(int id)
        {
            if (!User.IsInRole("Administrador"))
            {

                if (id.ToString() != User.Identity.Name)
                {
                    return Redirect("/Home/Restringido");
                }
            }
            var usuarios = repoUsuario.ObtenerPorId(id);
            return View(usuarios);
        }

        // GET: Usuarios/Create
        [Authorize(Policy = "Administrador")]
        public ActionResult Create()
        {
            ViewBag.Roles = Usuario.ObtenerRoles();
            return View();
        }

        // POST: Usuarios/Create
        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Policy = "Administrador")]
        public ActionResult Create(Usuario usuario)
        {
            try
            {
                string hashed = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                       password: usuario.Password,
                       salt: System.Text.Encoding.ASCII.GetBytes(configuration["Salt"]),
                       prf: KeyDerivationPrf.HMACSHA1,
                       iterationCount: 1000,
                       numBytesRequested: 256 / 8));

                usuario.Password = hashed;

                if (usuario.AvatarFile != null)
                {
                    string wwwPath = environment.WebRootPath;
                    string path = Path.Combine(wwwPath, "Uploads");
                    if (!Directory.Exists(path))
                    {
                        Directory.CreateDirectory(path);
                    }
                    string fileName = Path.GetFileName(usuario.AvatarFile.FileName);
                    string pathCompleto = Path.Combine(path, fileName);
                    usuario.Avatar = Path.Combine("/Uploads", fileName);
                    using (FileStream stream = new FileStream(pathCompleto, FileMode.Create))
                    {
                        usuario.AvatarFile.CopyTo(stream);
                    }

                }
                repoUsuario.AltaUsuario(usuario);

                return RedirectToAction(nameof(Index));
            }
            catch (Exception e)
            {
                throw;
            }
        }

        // GET: Usuarios/Edit/5
        [Authorize]
        public ActionResult Edit(int id)
        {
            if (!User.IsInRole("Administrador"))
            {

                if (id.ToString() != User.Identity.Name)
                {
                    return Redirect("/Home/Restringido");
                }
            }
            var usuario = repoUsuario.ObtenerPorId(id);
            ViewBag.Roles = Usuario.ObtenerRoles();
            return View(usuario);
        }

        // POST: Usuarios/Edit/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize]
        public ActionResult Edit(int id, Usuario usuario)
        {

            try
            {
                if (!User.IsInRole("Administrador"))
                {

                    if (id.ToString() != User.Identity.Name)
                    {
                        return Redirect("/Home/Restringido");
                    }
                }
                Usuario u = null;
                u = repoUsuario.ObtenerPorId(id);
                u.Nombre = usuario.Nombre;
                u.Apellido = usuario.Apellido;
                u.Email = usuario.Email;
                if (usuario.AvatarFile != null)
                {
                    string wwwPath = environment.WebRootPath;
                    string path = Path.Combine(wwwPath, "Uploads");
                    if (!Directory.Exists(path))
                    {
                        Directory.CreateDirectory(path);
                    }
                    string fileName = Path.GetFileName(usuario.AvatarFile.FileName);
                    string pathCompleto = Path.Combine(path, fileName);
                    usuario.Avatar = Path.Combine("/Uploads", fileName);
                    using (FileStream stream = new FileStream(pathCompleto, FileMode.Create))
                    {
                        usuario.AvatarFile.CopyTo(stream);
                    }

                }

                u.Avatar = usuario.Avatar;
                if (User.IsInRole("Administrador"))
                {
                    u.Rol = usuario.Rol;
                }
                else
                {
                    u.Rol = u.Rol;
                }

                repoUsuario.ModificacionUsuario(u);
                if (User.IsInRole("Administrador"))
                {
                    return RedirectToAction(nameof(Index));
                }
                else
                {
                    return RedirectToAction(nameof(Details), new { id = id });
                }
            }
            catch (Exception e)
            {
                throw;
            }
        }

        // GET: Usuarios/Delete/5
        [Authorize(Policy = "Administrador")]
        public ActionResult Delete(int id)
        {
            var usuario = repoUsuario.ObtenerPorId(id);
            return View(usuario);
        }

        // POST: Usuarios/Delete/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Policy = "Administrador")]
        public ActionResult Delete(int id, Usuario usuario)
        {
            try
            {
                repoUsuario.BajaUsuario(id);
                return RedirectToAction(nameof(Index));
            }
            catch (Exception e)
            {
                throw;
            }
        }

        [Authorize]
        public ActionResult EditPassword(int id, string returnUrl)
        {
            if (!User.IsInRole("Administrador"))
            {

                if (id.ToString() != User.Identity.Name)
                {
                    return Redirect("/Home/Restringido");
                }
            }
            TempData["Mensaje"] = "";
            TempData["returnUrl"] = returnUrl;
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize]
        public ActionResult EditPassword(int id, CambioPassword p)
        {

            try
            {
                if (!User.IsInRole("Administrador"))
                {

                    if (id.ToString() != User.Identity.Name)
                    {
                        return Redirect("/Home/Restringido");
                    }
                }
                var returnUrl = String.IsNullOrEmpty(TempData["returnUrl"] as string) ? "/Home" : TempData["returnUrl"].ToString();
                string hashedPassVieja = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                       password: p.PasswordVieja,
                       salt: System.Text.Encoding.ASCII.GetBytes(configuration["Salt"]),
                       prf: KeyDerivationPrf.HMACSHA1,
                       iterationCount: 1000,
                       numBytesRequested: 256 / 8));
                string hashedPassNueva = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                       password: p.PasswordNueva,
                       salt: System.Text.Encoding.ASCII.GetBytes(configuration["Salt"]),
                       prf: KeyDerivationPrf.HMACSHA1,
                       iterationCount: 1000,
                       numBytesRequested: 256 / 8));
                string hashedPassConfirmacion = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                       password: p.PasswordConfirmacion,
                       salt: System.Text.Encoding.ASCII.GetBytes(configuration["Salt"]),
                       prf: KeyDerivationPrf.HMACSHA1,
                       iterationCount: 1000,
                       numBytesRequested: 256 / 8));

                Usuario u = repoUsuario.ObtenerPorId(id);
                string PassVieja = u.Password;

                if (PassVieja == hashedPassVieja)
                {
                    if (hashedPassNueva == hashedPassConfirmacion)
                    {
                        p.PasswordNueva = hashedPassNueva;
                        p.PasswordConfirmacion = hashedPassConfirmacion;
                        repoUsuario.ModificacionPassword(id, p);
                    }
                    else
                    {
                        ModelState.AddModelError("", "El campo contraseña nueva y confirme contraseña no coinciden.");
                        TempData["returnUrl"] = returnUrl;

                        return View();
                    }

                    TempData["Mensaje"] = "Su contraseña a sido modificada.";
                    TempData["returnUrl"] = returnUrl;
                    return View();
                }
                else
                {
                    ModelState.AddModelError("", "Su contraseña actual no coincide con la ingresada.");
                    TempData["returnUrl"] = returnUrl;
                    return View();
                }
            }
            catch (Exception e)
            {
                throw;
            }
        }

    }
}