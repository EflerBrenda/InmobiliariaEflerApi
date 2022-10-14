using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using InmobiliariaEfler.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;

namespace InmobiliariaEfler.Controllers
{
    public class PropietariosController : Controller
    {
        private RepositorioPropietario repo;
        public PropietariosController(IConfiguration configuration)
        {
            repo = new RepositorioPropietario(configuration);
        }
        // GET: Propietarios
        [Authorize]
        public ActionResult Index()
        {
            var propietarios = repo.ObtenerPropietarios();
            return View(propietarios);
        }

        // GET: Propietarios/Details/5
        [Authorize]
        public ActionResult Details(int id)
        {
            var propietario = repo.ObtenerPorId(id);
            return View(propietario);
        }

        // GET: Propietarios/Create
        [Authorize]
        public ActionResult Create()
        {

            return View();
        }

        // POST: Propietarios/Create
        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize]
        public ActionResult Create(Propietario propietario)
        {
            try
            {
                repo.AltaPropietario(propietario);
                return RedirectToAction(nameof(Index));
            }
            catch (Exception e)
            {
                throw;
            }
        }

        // GET: Propietarios/Edit/5
        [Authorize]
        public ActionResult Edit(int id)
        {
            var propietario = repo.ObtenerPorId(id);
            return View(propietario);
        }

        // POST: Propietarios/Edit/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize]
        public ActionResult Edit(int id, Propietario propietario)
        {
            Propietario p = null;
            try
            {
                p = repo.ObtenerPorId(id);
                p.Nombre = propietario.Nombre;
                p.Apellido = propietario.Apellido;
                p.DNI = propietario.DNI;
                p.Telefono = propietario.Telefono;
                p.Email = propietario.Email;
                repo.ModificacionPropietario(p);
                return RedirectToAction(nameof(Index));
            }
            catch (Exception e)
            {
                throw;
            }
        }

        // GET: Propietarios/Delete/5
        [Authorize]
        public ActionResult Delete(int id)
        {
            var propietario = repo.ObtenerPorId(id);
            return View(propietario);
        }

        // POST: Propietarios/Delete/5
        [Authorize(Policy = "Administrador")]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Delete(int id, Propietario propietario)
        {
            try
            {

                repo.BajaPropietario(id);
                return RedirectToAction(nameof(Index));
            }
            catch (Exception e)
            {
                throw;
            }
        }
        [Authorize]
        public ActionResult VerInmuebles(int id)
        {
            var inmuebles = repo.ObtenerInmueblesPropios(id);
            return View(inmuebles);
        }
    }
}