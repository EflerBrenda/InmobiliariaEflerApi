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
    public class ContratosController : Controller
    {
        private RepositorioContrato repoContrato;
        private RepositorioInmueble repoInmueble;
        private RepositorioInquilino repoInquilino;
        public ContratosController(IConfiguration configuration)
        {
            repoContrato = new RepositorioContrato(configuration);
            repoInmueble = new RepositorioInmueble(configuration);
            repoInquilino = new RepositorioInquilino(configuration);
        }
        // GET: Contratos
        [Authorize]
        public ActionResult Index()
        {
            var contrato = repoContrato.ObtenerContratos();
            return View(contrato);

        }

        // GET: Contratos/Details/5
        [Authorize]
        public ActionResult Details(int id)
        {
            var contrato = repoContrato.ObtenerPorId(id);
            return View(contrato);
        }

        // GET: Contratos/Create
        [Authorize]
        public ActionResult Create()
        {
            return obtenerVista();
        }

        // POST: Contratos/Create
        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize]
        public ActionResult Create(Contrato contrato)
        {
            try
            {
                if (contrato.IdInmueble == null || contrato.IdInmueble < 0)
                {
                    ModelState.AddModelError("", "Debe ingresar un inmueble.");
                    return obtenerVista();
                }
                if (contrato.FechaDesde == null || contrato.FechaDesde.Date.ToString("yyyy-MM-dd") == "0001-01-01")
                {
                    ModelState.AddModelError("", "Debe ingresar una fecha valida desde.");
                    return obtenerVista();
                }
                if (contrato.FechaHasta == null || contrato.FechaHasta.Date.ToString("yyyy-MM-dd") == "0001-01-01")
                {
                    ModelState.AddModelError("", "Debe ingresar una fecha valida hasta.");
                    return obtenerVista();
                }
                if (contrato.FechaHasta > contrato.FechaDesde)
                {
                    ModelState.AddModelError("", "La fecha hasta no puede ser mayor que la fecha desde.");
                    return obtenerVista();
                }
                Contrato c = repoContrato.ComprobarDisponibilidad(contrato);
                if (c == null)
                {
                    ModelState.AddModelError("", "Inmueble no disponible en esas fechas");
                    return obtenerVista();
                }
                repoContrato.AltaContrato(contrato);
                return RedirectToAction(nameof(Index));
            }
            catch (Exception e)
            {
                ModelState.AddModelError("", "Error inesperado, por favor vuelva a intentarlo");
                return obtenerVista();
            }
        }



        // GET: Contratos/Edit/5
        [Authorize]
        public ActionResult Edit(int id)
        {

            var contrato = repoContrato.ObtenerPorId(id);
            return View(contrato);
        }

        // POST: Contratos/Edit/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize]
        public ActionResult Edit(int id, Contrato contrato)
        {
            try
            {
                if (contrato.IdInmueble == null || contrato.IdInmueble < 0)
                {
                    ModelState.AddModelError("", "Debe ingresar un inmueble.");
                    return obtenerVista();
                }
                if (contrato.FechaDesde == null || contrato.FechaDesde.Date.ToString("yyyy-MM-dd") == "0001-01-01")
                {
                    ModelState.AddModelError("", "Debe ingresar una fecha valida desde.");
                    return obtenerVista();
                }
                if (contrato.FechaHasta == null || contrato.FechaHasta.Date.ToString("yyyy-MM-dd") == "0001-01-01")
                {
                    ModelState.AddModelError("", "Debe ingresar una fecha valida hasta.");
                    return obtenerVista();
                }
                if (contrato.FechaHasta < contrato.FechaDesde)
                {
                    ModelState.AddModelError("", "La fecha hasta no puede ser menor que la fecha desde.");
                    return obtenerVista();
                }

                Contrato c = repoContrato.ComprobarDisponibilidad(contrato);
                if (c == null)
                {
                    ModelState.AddModelError("", "Inmueble no disponible en esas fechas");
                    return obtenerVista();
                }
                repoContrato.ModificacionContrato(contrato);
                return RedirectToAction(nameof(Index));

            }
            catch (Exception e)
            {
                ModelState.AddModelError("", "Error inesperado, por favor vuelva a intentarlo");
                return obtenerVista();
            }
        }

        // GET: Contratos/Delete/5
        [Authorize]
        public ActionResult Delete(int id)
        {
            var contrato = repoContrato.ObtenerPorId(id);
            return View(contrato);
        }

        // POST: Contratos/Delete/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Policy = "Administrador")]
        public ActionResult Delete(int id, Contrato contrato)
        {
            try
            {
                Contrato cv = repoContrato.ObtenerContratoVigente(id);
                if (cv != null)
                {
                    ModelState.AddModelError("", "No se puede eliminar el contrato ya que esta vigente.");
                    return RedirectToAction(nameof(Delete), id);
                }

                repoContrato.BajaContrato(id);
                return RedirectToAction(nameof(Index));
            }
            catch (Exception e)
            {
                ModelState.AddModelError("", "Error inesperado, por favor vuelva a intentarlo");
                return RedirectToAction(nameof(Delete), id);
            }
        }

        [Authorize]
        public ActionResult VerContratosVigentes()
        {
            var contrato = repoContrato.ObtenerContratosVigentes();
            return View(contrato);

        }
        [Authorize]
        public ActionResult VerContratosNoVigentes()
        {
            var contrato = repoContrato.ObtenerContratosNoVigentes();
            return View(contrato);

        }
        [Authorize]
        public ActionResult RenovarContrato(int id)
        {
            var contrato = repoContrato.ObtenerPorId(id);
            return View(contrato);

        }
        [Authorize]
        public ActionResult VerPagos(int id)
        {
            var pagos = repoContrato.ObtenerPagosPorContrato(id);
            return View(pagos);

        }

        [Authorize]
        public ActionResult FiltrarDisponibles()
        {
            TempData["Error"] = "";
            TempData["FechaDesde"] = DateTime.Today.Date.ToString("yyyy-MM-dd");
            TempData["FechaHasta"] = DateTime.Today.Date.ToString("yyyy-MM-dd");
            return obtenerVistaInmueblesDisponibles();
        }


        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize]
        public ActionResult FiltrarDisponibles(DateTime fechaDesde, DateTime fechaHasta)
        {
            try
            {
                TempData["FechaDesde"] = fechaDesde.Date.ToString("yyyy-MM-dd");
                TempData["FechaHasta"] = fechaHasta.Date.ToString("yyyy-MM-dd");
                if (fechaDesde == null || fechaDesde.Date.ToString("yyyy-MM-dd") == "0001-01-01")
                {
                    TempData["Error"] = "Ingrese fecha desde valida.";

                    return obtenerVistaInmueblesDisponibles();
                }
                if (fechaHasta == null || fechaHasta.Date.ToString("yyyy-MM-dd") == "0001-01-01")
                {

                    TempData["Error"] = "Ingrese fecha hasta valida.";
                    return obtenerVistaInmueblesDisponibles();
                }
                if (fechaHasta < fechaDesde)
                {
                    TempData["Error"] = "La fecha hasta no debe ser menor a la fecha desde.";
                    return obtenerVistaInmueblesDisponibles();
                }
                var listaInmuebles = repoContrato.ObtenerInmueblesDisponibles(fechaDesde, fechaHasta);
                TempData["Error"] = "";
                return View(listaInmuebles);
            }
            catch (Exception e)
            {
                TempData["Error"] = "Error inesperado, por favor vuelva a intentarlo";
                return obtenerVistaInmueblesDisponibles();
            }
        }
        private ActionResult obtenerVistaInmueblesDisponibles()
        {
            var inmuebles = repoInmueble.ObtenerInmuebles();
            return View(inmuebles);
        }

        private ActionResult obtenerVista()
        {
            ViewBag.Inquilinos = repoInquilino.ObtenerInquilinos();
            ViewBag.Inmuebles = repoInmueble.ObtenerInmuebles();
            return View();
        }

    }
}