using Microsoft.Extensions.Configuration;
using MySql.Data.MySqlClient;
using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.Linq;
using System.Threading.Tasks;

namespace InmobiliariaEfler.Models
{
    public class RepositorioPropietario : RepositorioBase
    {
        public RepositorioPropietario(IConfiguration configuration) : base(configuration)
        {

        }
        public int AltaPropietario(Propietario p)
        {
            int res = -1;
            using (var connection = new MySqlConnection(connectionString))
            {
                string sql = @"INSERT INTO propietario (Nombre, Apellido, Dni, Telefono, Email) 
                VALUES (@nombre, @apellido, @dni, @telefono, @email); 
                SELECT LAST_INSERT_ID();";
                using (var command = new MySqlCommand(sql, connection))
                {
                    command.CommandType = CommandType.Text;
                    command.Parameters.AddWithValue("@nombre", p.Nombre);
                    command.Parameters.AddWithValue("@apellido", p.Apellido);
                    command.Parameters.AddWithValue("@dni", p.DNI);
                    command.Parameters.AddWithValue("@telefono", p.Telefono);
                    command.Parameters.AddWithValue("@email", p.Email);
                    connection.Open();
                    res = Convert.ToInt32(command.ExecuteScalar());
                    p.Id = res;
                    connection.Close();
                }
            }
            return res;
        }
        public int BajaPropietario(int id)
        {
            int res = -1;
            using (var connection = new MySqlConnection(connectionString))
            {
                string sql = $"DELETE FROM propietario WHERE id = @id";
                using (var command = new MySqlCommand(sql, connection))
                {
                    command.CommandType = CommandType.Text;
                    command.Parameters.AddWithValue("@id", id);
                    connection.Open();
                    res = command.ExecuteNonQuery();
                    connection.Close();
                }
            }
            return res;
        }
        public int ModificacionPropietario(Propietario p)
        {
            int res = -1;
            using (var connection = new MySqlConnection(connectionString))
            {
                string sql = $"UPDATE propietario SET nombre=@nombre, apellido=@apellido, dni=@dni, telefono=@telefono, email=@email WHERE id = @id";
                using (var command = new MySqlCommand(sql, connection))
                {
                    command.CommandType = CommandType.Text;
                    command.Parameters.AddWithValue("@id", p.Id);
                    command.Parameters.AddWithValue("@nombre", p.Nombre);
                    command.Parameters.AddWithValue("@apellido", p.Apellido);
                    command.Parameters.AddWithValue("@dni", p.DNI);
                    command.Parameters.AddWithValue("@telefono", p.Telefono);
                    command.Parameters.AddWithValue("@email", p.Email);
                    connection.Open();
                    res = command.ExecuteNonQuery();
                    connection.Close();
                }
            }
            return res;
        }
        public List<Propietario> ObtenerPropietarios()
        {
            List<Propietario> res = new List<Propietario>();
            using (var conn = new MySqlConnection(connectionString))
            {
                string sql = "SELECT id, nombre, apellido,dni,telefono,email FROM Propietario";
                using (var comm = new MySqlCommand(sql, conn))
                {
                    conn.Open();
                    var reader = comm.ExecuteReader();
                    while (reader.Read())
                    {
                        res.Add(new Propietario
                        {
                            Id = reader.GetInt32(0),
                            Nombre = reader.GetString(1),
                            Apellido = reader.GetString(2),
                            DNI = reader.GetString(3),
                            Telefono = reader.GetString(4),
                            Email = reader.GetString(5),

                        });
                    }
                    conn.Close();
                }
            }
            return res;
        }
        public Propietario ObtenerPorId(int id)
        {
            Propietario p = null;
            using (var connection = new MySqlConnection(connectionString))
            {
                string sql = @"SELECT id,nombre,apellido,dni,telefono,email 
                FROM propietario 
                WHERE id=@id";
                using (var command = new MySqlCommand(sql, connection))
                {
                    command.Parameters.Add("@id", MySqlDbType.Int32).Value = id;
                    command.CommandType = CommandType.Text;
                    connection.Open();
                    var reader = command.ExecuteReader();
                    if (reader.Read())
                    {
                        p = new Propietario
                        {
                            Id = reader.GetInt32(0),
                            Nombre = reader.GetString(1),
                            Apellido = reader.GetString(2),
                            DNI = reader.GetString(3),
                            Telefono = reader.GetString(4),
                            Email = reader.GetString(5)
                        };
                    }
                    connection.Close();
                }
            }
            return p;
        }
        public List<Inmueble> ObtenerInmueblesPropios(int id)
        {
            List<Inmueble> res = new List<Inmueble>();
            using (var conn = new MySqlConnection(connectionString))
            {
                string sql = @"SELECT i.id,direccion,ambientes,superficie,latitud,longitud,
                precio,oferta_activa,id_propietario,id_tipo,p.nombre,
                p.apellido,ti.descripcion,uso
                FROM inmueble i 
                JOIN propietario p ON(i.id_propietario = p.id) 
                JOIN tipo_inmueble ti ON (i.id_tipo = ti.id)
                WHERE p.id= @id;";
                using (var comm = new MySqlCommand(sql, conn))
                {

                    comm.Parameters.Add("@id", MySqlDbType.Int32).Value = id;
                    comm.CommandType = CommandType.Text;
                    conn.Open();
                    var reader = comm.ExecuteReader();
                    while (reader.Read())
                    {
                        res.Add(new Inmueble
                        {
                            Id = reader.GetInt32(0),
                            Direccion = reader.GetString(1),
                            Ambientes = reader.GetInt32(2),
                            Superficie = reader.GetDecimal(3),
                            Latitud = reader.GetDecimal(4),
                            Longitud = reader.GetDecimal(5),
                            Precio = reader.GetDecimal(6),
                            OfertaActiva = reader.GetBoolean(7),
                            IdPropietario = reader.GetInt32(8),
                            IdTipo = reader.GetInt32(9),
                            Duenio = new Propietario
                            {
                                Nombre = reader.GetString(10),
                                Apellido = reader.GetString(11),
                            },
                            TipoInmueble = new TipoInmueble
                            {
                                Descripcion = reader.GetString(12),
                            },
                            Uso = reader.GetInt32(13)
                        });
                    }
                    conn.Close();
                }
            }
            return res;
        }

    }


}
