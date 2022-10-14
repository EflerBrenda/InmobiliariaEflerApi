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
    public class RepositorioTipoInmueble : RepositorioBase
    {

        public RepositorioTipoInmueble(IConfiguration configuration) : base(configuration)
        {

        }
        public int AltaTipoInmueble(TipoInmueble t)
        {
            int res = -1;
            using (var connection = new MySqlConnection(connectionString))
            {
                string sql = @"INSERT INTO tipo_inmueble (descripcion) 
                VALUES (@descripcion); 
                SELECT LAST_INSERT_ID();";
                using (var command = new MySqlCommand(sql, connection))
                {
                    command.CommandType = CommandType.Text;
                    command.Parameters.AddWithValue("@descripcion", t.Descripcion);
                    connection.Open();
                    res = Convert.ToInt32(command.ExecuteScalar());
                    t.Id = res;
                    connection.Close();
                }
            }
            return res;
        }
        public int BajaTipoInmueble(int id)
        {
            int res = -1;
            using (var connection = new MySqlConnection(connectionString))
            {
                string sql = @"DELETE FROM tipo_inmueble WHERE id = @id";
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
        public int ModificacionTipoInmueble(TipoInmueble t)
        {
            int res = -1;
            using (var connection = new MySqlConnection(connectionString))
            {
                string sql = @"UPDATE tipo_inmueble 
                SET descripcion=@descripcion 
                WHERE id = @id";
                using (var command = new MySqlCommand(sql, connection))
                {
                    command.CommandType = CommandType.Text;
                    command.Parameters.AddWithValue("@id", t.Id);
                    command.Parameters.AddWithValue("@descripcion", t.Descripcion);
                    connection.Open();
                    res = command.ExecuteNonQuery();
                    connection.Close();
                }
            }
            return res;
        }
        public List<TipoInmueble> ObtenerTipoInmueble()
        {
            List<TipoInmueble> res = new List<TipoInmueble>();
            using (var conn = new MySqlConnection(connectionString))
            {
                string sql = @"SELECT id, descripcion FROM tipo_inmueble";
                using (var comm = new MySqlCommand(sql, conn))
                {
                    conn.Open();
                    var reader = comm.ExecuteReader();
                    while (reader.Read())
                    {
                        res.Add(new TipoInmueble
                        {
                            Id = reader.GetInt32(0),
                            Descripcion = reader.GetString(1),
                        });
                    }
                    conn.Close();
                }
            }
            return res;
        }
        public TipoInmueble ObtenerPorId(int id)
        {
            TipoInmueble t = null;
            using (var connection = new MySqlConnection(connectionString))
            {
                string sql = @"SELECT id,descripcion FROM tipo_inmueble WHERE id=@id";
                using (var command = new MySqlCommand(sql, connection))
                {
                    command.Parameters.Add("@id", MySqlDbType.Int32).Value = id;
                    command.CommandType = CommandType.Text;
                    connection.Open();
                    var reader = command.ExecuteReader();
                    if (reader.Read())
                    {
                        t = new TipoInmueble
                        {
                            Id = reader.GetInt32(0),
                            Descripcion = reader.GetString(1)
                        };
                    }
                    connection.Close();
                }
            }
            return t;
        }

    }

}
