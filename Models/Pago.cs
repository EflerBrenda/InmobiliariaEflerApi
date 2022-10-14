using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
namespace InmobiliariaEfler.Models;

public class Pago
{
    public int Id { get; set; }

    [Display(Name = "Número de Pago")]
    public String NumeroPago { get; set; }

    [Display(Name = "Fecha de pago")]
    public DateTime FechaPago { get; set; }
    public decimal Importe { get; set; }

    [Display(Name = "Número de contrato")]
    public int IdContrato { get; set; }

    [ForeignKey(nameof(IdContrato))]
    public Contrato Contrato { get; set; }
}