using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
namespace InmobiliariaEfler.Models;

public class CambioPassword
{

    [Required, DataType(DataType.Password)]
    public string PasswordVieja { get; set; }

    [Required, DataType(DataType.Password)]
    public string PasswordNueva { get; set; }

    [Required, DataType(DataType.Password)]
    public string PasswordConfirmacion { get; set; }

}

