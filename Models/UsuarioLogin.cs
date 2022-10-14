using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
namespace InmobiliariaEfler.Models;

public class UsuarioLogin
{

    public string Email { get; set; }

    [Required, DataType(DataType.Password)]
    public string Password { get; set; }

}

