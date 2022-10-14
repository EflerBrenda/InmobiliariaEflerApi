using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
namespace InmobiliariaEfler.Models;

public class Inquilino
{
    public int Id { get; set; }
    public String Nombre { get; set; }
    public String Apellido { get; set; }
    public String DNI { get; set; }

    [Display(Name = "Teléfono")]
    public String Telefono { get; set; }
    public String Email { get; set; }

}