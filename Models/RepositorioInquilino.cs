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
    public class RepositorioInquilino : RepositorioBase
    {

        public RepositorioInquilino(IConfiguration configuration) : base(configuration)
        {

        }
        public int AltaInquilino(Inquilino i)
        {
            int res = -1;
            using (var connection = new MySqlConnection(connectionString))
            {
                string sql = @"INSERT INTO inquilino (Nombre, Apellido, Dni, Telefono, Email) 
                VALUES (@nombre, @apellido, @dni, @telefono, @email);
                SELECT LAST_INSERT_ID();";
                using (var command = new MySqlCommand(sql, connection))
                {
                    command.CommandType = CommandType.Text;
                    command.Parameters.AddWithValue("@nombre", i.Nombre);
                    command.Parameters.AddWithValue("@apellido", i.Apellido);
                    command.Parameters.AddWithValue("@dni", i.DNI);
                    command.Parameters.AddWithValue("@telefono", i.Telefono);
                    command.Parameters.AddWithValue("@email", i.Email);
                    connection.Open();
                    res = Convert.ToInt32(command.ExecuteScalar());
                    i.Id = res;
                    connection.Close();
                }
            }
            return res;
        }
        public int BajaInquilino(int id)
        {
            int res = -1;
            using (var connection = new MySqlConnection(connectionString))
            {
                string sql = $"DELETE FROM inquilino WHERE id = @id";
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
        public int ModificacionInquilino(Inquilino i)
        {
            int res = -1;
            using (var connection = new MySqlConnection(connectionString))
            {
                string sql = $"UPDATE inquilino SET nombre=@nombre, apellido=@apellido, dni=@dni, telefono=@telefono, email=@email WHERE id = @id";
                using (var command = new MySqlCommand(sql, connection))
                {
                    command.CommandType = CommandType.Text;
                    command.Parameters.AddWithValue("@id", i.Id);
                    command.Parameters.AddWithValue("@nombre", i.Nombre);
                    command.Parameters.AddWithValue("@apellido", i.Apellido);
                    command.Parameters.AddWithValue("@dni", i.DNI);
                    command.Parameters.AddWithValue("@telefono", i.Telefono);
                    command.Parameters.AddWithValue("@email", i.Email);
                    connection.Open();
                    res = command.ExecuteNonQuery();
                    connection.Close();
                }
            }
            return res;
        }
        public List<Inquilino> ObtenerInquilinos()
        {
            List<Inquilino> res = new List<Inquilino>();
            using (var conn = new MySqlConnection(connectionString))
            {
                string sql = "SELECT id, nombre, apellido,dni,telefono,email FROM inquilino";
                using (var comm = new MySqlCommand(sql, conn))
                {
                    conn.Open();
                    var reader = comm.ExecuteReader();
                    while (reader.Read())
                    {
                        res.Add(new Inquilino
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
        public Inquilino ObtenerPorId(int id)
        {
            Inquilino i = null;
            using (var connection = new MySqlConnection(connectionString))
            {
                string sql = $"SELECT id,nombre,apellido,dni,telefono,email FROM inquilino" +
                    $" WHERE id=@id";
                using (var command = new MySqlCommand(sql, connection))
                {
                    command.Parameters.Add("@id", MySqlDbType.Int32).Value = id;
                    command.CommandType = CommandType.Text;
                    connection.Open();
                    var reader = command.ExecuteReader();
                    if (reader.Read())
                    {
                        i = new Inquilino
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
            return i;
        }

    }

}
