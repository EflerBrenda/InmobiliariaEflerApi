using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
namespace InmobiliariaEfler.Models;

public class Propietario
{
    public int Id { get; set; }
    public String Nombre { get; set; }
    public String Apellido { get; set; }
    public String DNI { get; set; }
    [Display(Name = "Teléfono")]
    public String Telefono { get; set; }
    public String Email { get; set; }

    [Required, DataType(DataType.Password)]
    public string Password { get; set; }
}
