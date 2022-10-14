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
    public class RepositorioPago : RepositorioBase
    {

        public RepositorioPago(IConfiguration configuration) : base(configuration)
        {

        }
        public int AltaPago(Pago i)
        {
            int res = -1;
            using (var connection = new MySqlConnection(connectionString))
            {
                string sql = @"INSERT INTO pagos (numero_pago, fecha_pago, importe, id_contrato) 
                VALUES (@numero_pago, @fecha_pago, @importe, @id_contrato);
                SELECT LAST_INSERT_ID();";
                using (var command = new MySqlCommand(sql, connection))
                {
                    command.CommandType = CommandType.Text;
                    command.Parameters.AddWithValue("@numero_pago", i.NumeroPago);
                    command.Parameters.AddWithValue("@fecha_pago", i.FechaPago);
                    command.Parameters.AddWithValue("@importe", i.Importe);
                    command.Parameters.AddWithValue("@id_contrato", i.IdContrato);
                    connection.Open();
                    res = Convert.ToInt32(command.ExecuteScalar());
                    i.Id = res;
                    connection.Close();
                }
            }
            return res;
        }
        public int BajaPago(int id)
        {
            int res = -1;
            using (var connection = new MySqlConnection(connectionString))
            {
                string sql = @"DELETE FROM pagos WHERE id = @id";
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
        public int ModificacionPago(Pago p)
        {
            int res = -1;
            using (var connection = new MySqlConnection(connectionString))
            {
                string sql = @"UPDATE pagos 
                SET numero_pago= @numero_pago,fecha_pago= @fecha_pago, importe=@importe,id_contrato= @id_contrato 
                WHERE id = @id";
                using (var command = new MySqlCommand(sql, connection))
                {
                    command.CommandType = CommandType.Text;
                    command.Parameters.AddWithValue("@id", p.Id);
                    command.Parameters.AddWithValue("@numero_pago", p.NumeroPago);
                    command.Parameters.AddWithValue("@fecha_pago", p.FechaPago);
                    command.Parameters.AddWithValue("@importe", p.Importe);
                    command.Parameters.AddWithValue("@id_contrato", p.IdContrato);
                    connection.Open();
                    res = command.ExecuteNonQuery();
                    connection.Close();
                }
            }
            return res;
        }
        public List<Pago> ObtenerPagos()
        {
            List<Pago> res = new List<Pago>();
            using (var conn = new MySqlConnection(connectionString))
            {
                string sql = @"SELECT p.id, numero_pago, fecha_pago,importe,id_contrato,inm.direccion,inq.nombre,inq.apellido
                FROM pagos p
                JOIN contrato c ON(p.id_contrato =c.id)
                JOIN inquilino inq ON(c.id_inquilino = inq.id)
                JOIN inmueble inm ON(c.id_inmueble= inm.id)";
                using (var comm = new MySqlCommand(sql, conn))
                {
                    conn.Open();
                    var reader = comm.ExecuteReader();
                    while (reader.Read())
                    {
                        res.Add(new Pago
                        {
                            Id = reader.GetInt32(0),
                            NumeroPago = reader.GetString(1),
                            FechaPago = reader.GetDateTime(2),
                            Importe = reader.GetDecimal(3),
                            IdContrato = reader.GetInt32(4),
                            Contrato = new Contrato
                            {
                                Inmueble = new Inmueble
                                {
                                    Direccion = reader.GetString(5),
                                },
                                Inquilino = new Inquilino
                                {
                                    Nombre = reader.GetString(6),
                                    Apellido = reader.GetString(7),
                                }
                            }

                        });
                    }
                    conn.Close();
                }
            }
            return res;
        }
        public Pago ObtenerPorId(int id)
        {
            Pago i = null;
            using (var connection = new MySqlConnection(connectionString))
            {
                string sql = @"SELECT p.id, numero_pago, fecha_pago,importe,id_contrato,inm.direccion,inq.nombre,inq.apellido
                FROM pagos p
                JOIN contrato c ON(p.id_contrato =c.id)
                JOIN inquilino inq ON(c.id_inquilino = inq.id)
                JOIN inmueble inm ON(c.id_inmueble= inm.id)
                WHERE p.id=@id";
                using (var command = new MySqlCommand(sql, connection))
                {
                    command.Parameters.Add("@id", MySqlDbType.Int32).Value = id;
                    command.CommandType = CommandType.Text;
                    connection.Open();
                    var reader = command.ExecuteReader();
                    if (reader.Read())
                    {
                        i = new Pago
                        {
                            Id = reader.GetInt32(0),
                            NumeroPago = reader.GetString(1),
                            FechaPago = reader.GetDateTime(2),
                            Importe = reader.GetDecimal(3),
                            IdContrato = reader.GetInt32(4),
                            Contrato = new Contrato
                            {
                                Inmueble = new Inmueble
                                {
                                    Direccion = reader.GetString(5),
                                },
                                Inquilino = new Inquilino
                                {
                                    Nombre = reader.GetString(6),
                                    Apellido = reader.GetString(7),
                                }
                            }
                        };
                    }
                    connection.Close();
                }
            }
            return i;
        }

    }

}
