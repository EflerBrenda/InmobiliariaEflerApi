using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
namespace InmobiliariaEfler.Models;

public class Usuario
{
    public enum enRoles
    {
        Administrador = 1,
        Empleado = 2,
    }
    public int Id { get; set; }
    public String Nombre { get; set; }
    public String Apellido { get; set; }
    public string Email { get; set; }

    [Required, DataType(DataType.Password)]
    public string Password { get; set; }

    public string? Avatar { get; set; }

    [Display(Name = "Avatar")]
    public IFormFile AvatarFile { get; set; }
    public int Rol { get; set; }
    public string RolNombre => Rol > 0 ? ((enRoles)Rol).ToString() : "";

    public static IDictionary<int, string> ObtenerRoles()
    {
        SortedDictionary<int, string> roles = new SortedDictionary<int, string>();
        Type tipoEnumRol = typeof(enRoles);
        foreach (var valor in Enum.GetValues(tipoEnumRol))
        {
            roles.Add((int)valor, Enum.GetName(tipoEnumRol, valor));
        }
        return roles;
    }
}

