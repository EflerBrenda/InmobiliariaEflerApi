using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
namespace InmobiliariaEfler.Models;

public class Contrato
{
    [Display(Name = "Código")]
    public int Id { get; set; }

    [Display(Name = "Fecha de inicio")]
    public DateTime FechaDesde { get; set; }

    [Display(Name = "Fecha de finalización")]
    public DateTime FechaHasta { get; set; }

    [Display(Name = "Monto del alquiler")]
    public decimal MontoAlquiler { get; set; }

    [Display(Name = "Inmueble")]
    public int IdInmueble { get; set; }
    [ForeignKey(nameof(IdInmueble))]
    public Inmueble Inmueble { get; set; }

    [Display(Name = "Inquilino")]
    public int IdInquilino { get; set; }
    [ForeignKey(nameof(IdInquilino))]
    public Inquilino Inquilino { get; set; }


}