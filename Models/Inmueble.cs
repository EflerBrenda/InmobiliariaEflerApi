using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
namespace InmobiliariaEfler.Models;

public class Inmueble
{
    public enum enUsos
    {
        Residencial = 1,
        Comercial = 2,
    }
    public int Id { get; set; }
    [Display(Name = "Dirección")]
    public String Direccion { get; set; }
    public int Ambientes { get; set; }
    public decimal Superficie { get; set; }
    public decimal Latitud { get; set; }
    public decimal Longitud { get; set; }
    public decimal Precio { get; set; }

    public int Uso { get; set; }

    [Display(Name = "Oferta activa")]
    public Boolean OfertaActiva { get; set; }

    [Display(Name = "Dueño")]
    public int IdPropietario { get; set; }
    [ForeignKey(nameof(IdPropietario))]
    public Propietario Duenio { get; set; }

    [Display(Name = "Tipo Inmueble")]
    public int IdTipo { get; set; }
    [ForeignKey(nameof(IdTipo))]
    public TipoInmueble TipoInmueble { get; set; }

    public string UsoNombre => Uso > 0 ? ((enUsos)Uso).ToString() : "";
    public static IDictionary<int, string> ObtenerUsos()
    {
        SortedDictionary<int, string> usos = new SortedDictionary<int, string>();
        Type tipoEnumUso = typeof(enUsos);
        foreach (var valor in Enum.GetValues(tipoEnumUso))
        {
            usos.Add((int)valor, Enum.GetName(tipoEnumUso, valor));
        }
        return usos;
    }

}