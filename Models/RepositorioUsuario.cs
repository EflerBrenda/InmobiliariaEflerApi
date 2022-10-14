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
    public class RepositorioUsuario : RepositorioBase
    {
        public RepositorioUsuario(IConfiguration configuration) : base(configuration)
        {

        }
        public int AltaUsuario(Usuario u)
        {
            int res = -1;
            using (var connection = new MySqlConnection(connectionString))
            {
                string sql = @"INSERT INTO usuario (Nombre, Apellido, Email, Password, Avatar,rol) 
                    VALUES (@nombre, @apellido, @email, @password, @avatar, @rol);
                    SELECT LAST_INSERT_ID();";
                using (var command = new MySqlCommand(sql, connection))
                {
                    command.CommandType = CommandType.Text;
                    command.Parameters.AddWithValue("@nombre", u.Nombre);
                    command.Parameters.AddWithValue("@apellido", u.Apellido);
                    command.Parameters.AddWithValue("@email", u.Email);
                    command.Parameters.AddWithValue("@password", u.Password);
                    if (String.IsNullOrEmpty(u.Avatar))
                        command.Parameters.AddWithValue("@avatar", DBNull.Value);
                    else
                        command.Parameters.AddWithValue("@avatar", u.Avatar);
                    command.Parameters.AddWithValue("@rol", u.Rol);
                    connection.Open();
                    res = Convert.ToInt32(command.ExecuteScalar());
                    u.Id = res;
                    connection.Close();
                }
            }
            return res;
        }
        public int BajaUsuario(int id)
        {
            int res = -1;
            using (var connection = new MySqlConnection(connectionString))
            {
                string sql = @"DELETE FROM usuario WHERE id = @id";
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
        public int ModificacionUsuario(Usuario u)
        {
            int res = -1;
            using (var connection = new MySqlConnection(connectionString))
            {
                string sql = @"UPDATE usuario 
                SET nombre= @nombre, apellido=@apellido, email=@email, avatar=@avatar, rol=@rol
                WHERE id = @id";
                using (var command = new MySqlCommand(sql, connection))
                {
                    command.CommandType = CommandType.Text;
                    command.Parameters.AddWithValue("@id", u.Id);
                    command.Parameters.AddWithValue("@nombre", u.Nombre);
                    command.Parameters.AddWithValue("@apellido", u.Apellido);
                    command.Parameters.AddWithValue("@email", u.Email);
                    command.Parameters.AddWithValue("@avatar", u.Avatar);
                    command.Parameters.AddWithValue("@rol", u.Rol);
                    connection.Open();
                    res = command.ExecuteNonQuery();
                    connection.Close();
                }
            }
            return res;
        }
        public List<Usuario> ObtenerUsuarios()
        {
            List<Usuario> res = new List<Usuario>();
            using (var conn = new MySqlConnection(connectionString))
            {
                string sql = @"SELECT id, Nombre, Apellido, Email, Password, Avatar,rol 
                            FROM usuario";
                using (var comm = new MySqlCommand(sql, conn))
                {
                    conn.Open();
                    var reader = comm.ExecuteReader();
                    while (reader.Read())
                    {
                        res.Add(new Usuario
                        {
                            Id = reader.GetInt32(0),
                            Nombre = reader.GetString(1),
                            Apellido = reader.GetString(2),
                            Email = reader.GetString(3),
                            Password = reader.GetString(4),
                            Avatar = reader["Avatar"].ToString(),
                            Rol = reader.GetInt32(6)

                        });
                    }
                    conn.Close();
                }
            }
            return res;
        }
        public Usuario ObtenerPorId(int id)
        {
            Usuario u = null;
            using (var connection = new MySqlConnection(connectionString))
            {
                string sql = @"SELECT id, Nombre, Apellido, Email, Password, Avatar,rol 
                            FROM usuario 
                            WHERE id=@id";
                using (var command = new MySqlCommand(sql, connection))
                {
                    command.Parameters.Add("@id", MySqlDbType.Int32).Value = id;
                    command.CommandType = CommandType.Text;
                    connection.Open();
                    var reader = command.ExecuteReader();
                    if (reader.Read())
                    {
                        u = new Usuario
                        {
                            Id = reader.GetInt32(0),
                            Nombre = reader.GetString(1),
                            Apellido = reader.GetString(2),
                            Email = reader.GetString(3),
                            Password = reader.GetString(4),
                            Avatar = reader["Avatar"].ToString(),
                            Rol = reader.GetInt32(6)
                        };
                    }
                    connection.Close();
                }
            }
            return u;
        }
        public Usuario ObtenerPorEmail(string email)
        {
            Usuario u = null;
            using (MySqlConnection connection = new MySqlConnection(connectionString))
            {
                string sql = @"SELECT id, Nombre, Apellido, Email, Password, Avatar,rol 
                            FROM usuario 
                            WHERE Email=@email";
                using (MySqlCommand command = new MySqlCommand(sql, connection))
                {
                    command.CommandType = CommandType.Text;
                    command.Parameters.Add("@email", MySqlDbType.VarChar).Value = email;
                    connection.Open();
                    var reader = command.ExecuteReader();
                    if (reader.Read())
                    {
                        u = new Usuario
                        {
                            Id = reader.GetInt32(0),
                            Nombre = reader.GetString(1),
                            Apellido = reader.GetString(2),
                            Email = reader.GetString(3),
                            Password = reader.GetString(4),
                            Avatar = reader["Avatar"].ToString(),
                            Rol = reader.GetInt32(6)
                        };
                    }
                    connection.Close();
                }
            }
            return u;
        }
        public int ModificacionPassword(int id, CambioPassword p)
        {
            int res = -1;
            using (var connection = new MySqlConnection(connectionString))
            {
                string sql = @"UPDATE usuario 
                SET password=@password
                WHERE id = @id";
                using (var command = new MySqlCommand(sql, connection))
                {
                    command.CommandType = CommandType.Text;
                    command.Parameters.AddWithValue("@id", id);
                    command.Parameters.AddWithValue("@password", p.PasswordConfirmacion);
                    connection.Open();
                    res = command.ExecuteNonQuery();
                    connection.Close();
                }
            }
            return res;
        }


    }

}
