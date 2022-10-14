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
    public class PagosController : Controller
    {
        private RepositorioPago repoPago;
        private RepositorioContrato repoContrato;
        public PagosController(IConfiguration configuration)
        {
            repoPago = new RepositorioPago(configuration);
            repoContrato = new RepositorioContrato(configuration);
        }
        // GET: Pagos
        public ActionResult Index()
        {
            var pagos = repoPago.ObtenerPagos();
            return View(pagos);
        }

        // GET: Pagos/Details/5
        public ActionResult Details(int id)
        {
            var pago = repoPago.ObtenerPorId(id);
            return View(pago);
        }

        // GET: Pagos/Create
        public ActionResult Create()
        {
            ViewBag.Contratos = repoContrato.ObtenerContratos();
            return View();
        }

        // POST: Pagos/Create
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Create(Pago pago)
        {
            try
            {

                repoPago.AltaPago(pago);
                return RedirectToAction(nameof(Index));
            }
            catch (Exception e)
            {
                throw;
            }
        }

        // GET: Pagos/Edit/5
        public ActionResult Edit(int id)
        {
            ViewBag.Contratos = repoContrato.ObtenerContratos();
            var pago = repoPago.ObtenerPorId(id);
            return View(pago);
        }

        // POST: Pagos/Edit/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Edit(int id, Pago pago)
        {
            Pago p = null;
            try
            {
                p = repoPago.ObtenerPorId(id);
                p.NumeroPago = pago.NumeroPago;
                p.FechaPago = pago.FechaPago;
                p.Importe = pago.Importe;
                p.IdContrato = pago.IdContrato;
                repoPago.ModificacionPago(p);
                return RedirectToAction(nameof(Index));
            }
            catch (Exception e)
            {
                throw;
            }
        }

        // GET: Pagos/Delete/5
        public ActionResult Delete(int id)
        {
            var pago = repoPago.ObtenerPorId(id);
            return View(pago);
        }

        // POST: Pagos/Delete/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Policy = "Administrador")]
        public ActionResult Delete(int id, IFormCollection collection)
        {
            try
            {
                // TODO: Add delete logic here
                repoPago.BajaPago(id);
                return RedirectToAction(nameof(Index));
            }
            catch (Exception e)
            {
                throw;
            }
        }
    }
}