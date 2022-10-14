using System;
using System.Collections.Generic;
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
    public class TipoInmueblesController : Controller
    {
        private RepositorioTipoInmueble repoTipoInmueble;
        public TipoInmueblesController(IConfiguration configuration)
        {
            repoTipoInmueble = new RepositorioTipoInmueble(configuration);
        }
        // GET: TipoInmuebles
        [Authorize]
        public ActionResult Index()
        {
            var tipoInmuebles = repoTipoInmueble.ObtenerTipoInmueble();
            return View(tipoInmuebles);

        }

        // GET: TipoInmuebles/Details/5
        [Authorize]
        public ActionResult Details(int id)
        {
            var tipoInmuebles = repoTipoInmueble.ObtenerPorId(id);
            return View(tipoInmuebles);
        }

        // GET: TipoInmuebles/Create
        [Authorize]
        public ActionResult Create()
        {
            return View();
        }

        // POST: TipoInmuebles/Create
        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize]
        public ActionResult Create(TipoInmueble tipoInmueble)
        {
            try
            {
                repoTipoInmueble.AltaTipoInmueble(tipoInmueble);
                return RedirectToAction(nameof(Index));
            }
            catch (Exception e)
            {
                throw;
            }
        }

        // GET: TipoInmuebles/Edit/5
        [Authorize]
        public ActionResult Edit(int id)
        {
            var tipoInmuebles = repoTipoInmueble.ObtenerPorId(id);
            return View(tipoInmuebles);
        }

        // POST: TipoInmuebles/Edit/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize]
        public ActionResult Edit(int id, TipoInmueble tipoInmueble)
        {
            TipoInmueble t = null;
            try
            {
                t = repoTipoInmueble.ObtenerPorId(id);
                t.Descripcion = tipoInmueble.Descripcion;
                repoTipoInmueble.ModificacionTipoInmueble(t);
                return RedirectToAction(nameof(Index));
            }
            catch (Exception e)
            {
                throw;
            }
        }

        // GET: TipoInmuebles/Delete/5
        [Authorize]
        public ActionResult Delete(int id)
        {
            var tipoInmuebles = repoTipoInmueble.ObtenerPorId(id);
            return View(tipoInmuebles);
        }

        // POST: TipoInmuebles/Delete/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Policy = "Administrador")]
        public ActionResult Delete(int id, TipoInmueble tipoInmueble)
        {
            try
            {
                repoTipoInmueble.BajaTipoInmueble(id);
                return RedirectToAction(nameof(Index));
            }
            catch (Exception e)
            {
                throw;
            }
        }
    }
}