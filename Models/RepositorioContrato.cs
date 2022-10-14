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
    public class RepositorioContrato : RepositorioBase
    {

        public RepositorioContrato(IConfiguration configuration) : base(configuration)
        {

        }
        public int AltaContrato(Contrato c)
        {
            int res = -1;
            using (var connection = new MySqlConnection(connectionString))
            {
                string sql = @"INSERT INTO contrato (fecha_desde,fecha_hasta,monto_alquiler,id_inmueble,id_inquilino) 
                VALUES (@fecha_desde,@fecha_hasta,@monto_alquiler,@id_inmueble,@id_inquilino); 
                SELECT LAST_INSERT_ID();";
                using (var command = new MySqlCommand(sql, connection))
                {
                    command.CommandType = CommandType.Text;
                    command.Parameters.AddWithValue("@fecha_desde", c.FechaDesde);
                    command.Parameters.AddWithValue("@fecha_hasta", c.FechaHasta);
                    command.Parameters.AddWithValue("@monto_alquiler", c.MontoAlquiler);
                    command.Parameters.AddWithValue("@id_inmueble", c.IdInmueble);
                    command.Parameters.AddWithValue("@id_inquilino", c.IdInquilino);
                    connection.Open();
                    res = Convert.ToInt32(command.ExecuteScalar());
                    c.Id = res;
                    connection.Close();
                }
            }
            return res;
        }
        public int BajaContrato(int id)
        {
            int res = -1;
            using (var connection = new MySqlConnection(connectionString))
            {
                string sql = @"DELETE FROM contrato WHERE id = @id";
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
        public int ModificacionContrato(Contrato c)
        {
            int res = -1;
            using (var connection = new MySqlConnection(connectionString))
            {
                string sql = @"UPDATE contrato SET fecha_desde= @fecha_desde, 
                fecha_hasta= @fecha_hasta,monto_alquiler= @monto_alquiler
                WHERE id = @id";
                //Falta editar el anterior inmueble a activo de nuevo.
                using (var command = new MySqlCommand(sql, connection))
                {
                    command.CommandType = CommandType.Text;
                    command.Parameters.AddWithValue("@id", c.Id);
                    command.Parameters.AddWithValue("@fecha_desde", c.FechaDesde);
                    command.Parameters.AddWithValue("@fecha_hasta", c.FechaHasta);
                    command.Parameters.AddWithValue("@monto_alquiler", c.MontoAlquiler);
                    connection.Open();
                    res = command.ExecuteNonQuery();
                    connection.Close();
                }
            }
            return res;
        }
        public List<Contrato> ObtenerContratos()
        {
            List<Contrato> res = new List<Contrato>();
            using (var conn = new MySqlConnection(connectionString))
            {
                string sql = @"SELECT c.id, fecha_desde, fecha_hasta,monto_alquiler,id_inmueble,
                id_inquilino,i.direccion,inq.nombre,inq.apellido 
                FROM contrato c 
                JOIN inmueble i ON (i.id =c.id_inmueble) 
                JOIN inquilino inq ON (inq.id =c.id_inquilino)
                ORDER BY fecha_desde asc;";
                using (var comm = new MySqlCommand(sql, conn))
                {
                    conn.Open();
                    var reader = comm.ExecuteReader();
                    while (reader.Read())
                    {
                        res.Add(new Contrato
                        {
                            Id = reader.GetInt32(0),
                            FechaDesde = reader.GetDateTime(1),
                            FechaHasta = reader.GetDateTime(2),
                            MontoAlquiler = reader.GetDecimal(3),
                            IdInmueble = reader.GetInt32(4),
                            IdInquilino = reader.GetInt32(5),
                            Inmueble = new Inmueble
                            {
                                Direccion = reader.GetString(6),
                            },
                            Inquilino = new Inquilino
                            {
                                Nombre = reader.GetString(7),
                                Apellido = reader.GetString(8),
                            }

                        });
                    }
                    conn.Close();
                }
            }
            return res;
        }
        public Contrato ObtenerPorId(int id)
        {
            Contrato c = null;
            using (var connection = new MySqlConnection(connectionString))
            {
                string sql = @"SELECT c.id, fecha_desde, fecha_hasta,monto_alquiler,id_inmueble,
                id_inquilino,i.direccion,inq.nombre,inq.apellido 
                FROM contrato c 
                JOIN inmueble i ON (i.id =c.id_inmueble) 
                JOIN inquilino inq ON (inq.id =c.id_inquilino)
                WHERE c.id= @id;";
                using (var command = new MySqlCommand(sql, connection))
                {
                    command.Parameters.Add("@id", MySqlDbType.Int32).Value = id;
                    command.CommandType = CommandType.Text;
                    connection.Open();
                    var reader = command.ExecuteReader();
                    if (reader.Read())
                    {
                        c = new Contrato
                        {
                            Id = reader.GetInt32(0),
                            FechaDesde = reader.GetDateTime(1),
                            FechaHasta = reader.GetDateTime(2),
                            MontoAlquiler = reader.GetDecimal(3),
                            IdInmueble = reader.GetInt32(4),
                            IdInquilino = reader.GetInt32(5),
                            Inmueble = new Inmueble
                            {
                                Direccion = reader.GetString(6),
                            },
                            Inquilino = new Inquilino
                            {
                                Nombre = reader.GetString(7),
                                Apellido = reader.GetString(8),
                            }
                        };
                    }
                    connection.Close();
                }
            }
            return c;
        }
        public List<Contrato> ObtenerContratosVigentes()
        {
            List<Contrato> res = new List<Contrato>();
            using (var conn = new MySqlConnection(connectionString))
            {
                string sql = @"SELECT c.id, fecha_desde, fecha_hasta,monto_alquiler,id_inmueble,
                id_inquilino,i.direccion,inq.nombre,inq.apellido 
                FROM contrato c 
                JOIN inmueble i ON (i.id =c.id_inmueble) 
                JOIN inquilino inq ON (inq.id =c.id_inquilino)
                WHERE fecha_desde<= CURDATE() AND fecha_hasta>= CURDATE()";
                using (var comm = new MySqlCommand(sql, conn))
                {
                    conn.Open();
                    var reader = comm.ExecuteReader();
                    while (reader.Read())
                    {
                        res.Add(new Contrato
                        {
                            Id = reader.GetInt32(0),
                            FechaDesde = reader.GetDateTime(1),
                            FechaHasta = reader.GetDateTime(2),
                            MontoAlquiler = reader.GetDecimal(3),
                            IdInmueble = reader.GetInt32(4),
                            IdInquilino = reader.GetInt32(5),
                            Inmueble = new Inmueble
                            {
                                Direccion = reader.GetString(6),
                            },
                            Inquilino = new Inquilino
                            {
                                Nombre = reader.GetString(7),
                                Apellido = reader.GetString(8),
                            }

                        });
                    }
                    conn.Close();
                }
            }
            return res;
        }
        public List<Contrato> ObtenerContratosNoVigentes()
        {
            List<Contrato> res = new List<Contrato>();
            using (var conn = new MySqlConnection(connectionString))
            {
                string sql = @"SELECT c.id, fecha_desde, fecha_hasta,monto_alquiler,id_inmueble,
                id_inquilino,i.direccion,inq.nombre,inq.apellido 
                FROM contrato c 
                JOIN inmueble i ON (i.id =c.id_inmueble) 
                JOIN inquilino inq ON (inq.id =c.id_inquilino)
                WHERE fecha_desde<= CURDATE() AND fecha_hasta<= CURDATE()";
                using (var comm = new MySqlCommand(sql, conn))
                {
                    conn.Open();
                    var reader = comm.ExecuteReader();
                    while (reader.Read())
                    {
                        res.Add(new Contrato
                        {
                            Id = reader.GetInt32(0),
                            FechaDesde = reader.GetDateTime(1),
                            FechaHasta = reader.GetDateTime(2),
                            MontoAlquiler = reader.GetDecimal(3),
                            IdInmueble = reader.GetInt32(4),
                            IdInquilino = reader.GetInt32(5),
                            Inmueble = new Inmueble
                            {
                                Direccion = reader.GetString(6),
                            },
                            Inquilino = new Inquilino
                            {
                                Nombre = reader.GetString(7),
                                Apellido = reader.GetString(8),
                            }

                        });
                    }
                    conn.Close();
                }
            }
            return res;
        }
        public List<Pago> ObtenerPagosPorContrato(int id)
        {
            List<Pago> res = new List<Pago>();
            using (var conn = new MySqlConnection(connectionString))
            {
                string sql = @"SELECT p.id, numero_pago, fecha_pago,importe,id_contrato,inm.direccion,inq.nombre,inq.apellido
                FROM pagos p
                JOIN contrato c ON(p.id_contrato =c.id)
                JOIN inquilino inq ON(c.id_inquilino = inq.id)
                JOIN inmueble inm ON(c.id_inmueble= inm.id)
                WHERE c.id= @id;";
                using (var comm = new MySqlCommand(sql, conn))
                {
                    comm.Parameters.Add("@id", MySqlDbType.Int32).Value = id;
                    comm.CommandType = CommandType.Text;
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
        public Contrato ObtenerContratoVigente(int id)
        {
            Contrato c = null;
            using (var connection = new MySqlConnection(connectionString))
            {
                string sql = @"SELECT c.id, fecha_desde, fecha_hasta,monto_alquiler,id_inmueble,
                id_inquilino,i.direccion,inq.nombre,inq.apellido 
                FROM contrato c 
                JOIN inmueble i ON (i.id =c.id_inmueble) 
                JOIN inquilino inq ON (inq.id =c.id_inquilino)
                WHERE c.id= @id AND fecha_desde<= CURDATE() AND fecha_hasta>= CURDATE();";
                using (var command = new MySqlCommand(sql, connection))
                {
                    command.Parameters.Add("@id", MySqlDbType.Int32).Value = id;
                    command.CommandType = CommandType.Text;
                    connection.Open();
                    var reader = command.ExecuteReader();
                    if (reader.Read())
                    {
                        c = new Contrato
                        {
                            Id = reader.GetInt32(0),
                            FechaDesde = reader.GetDateTime(1),
                            FechaHasta = reader.GetDateTime(2),
                            MontoAlquiler = reader.GetDecimal(3),
                            IdInmueble = reader.GetInt32(4),
                            IdInquilino = reader.GetInt32(5),
                            Inmueble = new Inmueble
                            {
                                Direccion = reader.GetString(6),
                            },
                            Inquilino = new Inquilino
                            {
                                Nombre = reader.GetString(7),
                                Apellido = reader.GetString(8),
                            }
                        };
                    }
                    connection.Close();
                }
            }
            return c;
        }
        public List<Inmueble> ObtenerInmueblesDisponibles(DateTime fechaDesde, DateTime fechaHasta)
        {
            List<Inmueble> res = new List<Inmueble>();
            using (var conn = new MySqlConnection(connectionString))
            {
                string sql = @"SELECT i.id,direccion,ambientes,superficie,latitud,longitud,
                precio,oferta_activa,id_propietario,id_tipo,p.nombre,
                p.apellido,ti.descripcion,uso
                FROM contrato c 
                JOIN inmueble i ON (i.id =c.id_inmueble) 
                JOIN propietario p ON(i.id_propietario = p.id) 
                JOIN tipo_inmueble ti ON (i.id_tipo = ti.id)
                WHERE (fecha_desde NOT BETWEEN @fechaDesde AND @fechaHasta) AND (fecha_hasta NOT BETWEEN @fechaDesde AND @fechaHasta)";
                using (var comm = new MySqlCommand(sql, conn))
                {
                    comm.Parameters.Add("@fechaDesde", MySqlDbType.DateTime).Value = fechaDesde;
                    comm.Parameters.Add("@fechaHasta", MySqlDbType.DateTime).Value = fechaHasta;
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
        public Contrato ComprobarDisponibilidad(Contrato contrato)
        {
            Contrato c = null;
            using (var connection = new MySqlConnection(connectionString))
            {
                string sql = @"SELECT c.id, fecha_desde, fecha_hasta,monto_alquiler,id_inmueble,
                id_inquilino,i.direccion,inq.nombre,inq.apellido 
                FROM contrato c 
                JOIN inmueble i ON (i.id =c.id_inmueble) 
                JOIN inquilino inq ON (inq.id =c.id_inquilino)
                WHERE @fechaDesde NOT BETWEEN fecha_desde AND fecha_hasta AND id_inmueble= @idInmueble ";
                using (var command = new MySqlCommand(sql, connection))
                {
                    command.Parameters.Add("@fechaDesde", MySqlDbType.DateTime).Value = contrato.FechaDesde;
                    command.Parameters.Add("@idInmueble", MySqlDbType.Int32).Value = contrato.IdInmueble;
                    command.CommandType = CommandType.Text;
                    connection.Open();
                    var reader = command.ExecuteReader();
                    if (reader.Read())
                    {
                        c = new Contrato
                        {
                            Id = reader.GetInt32(0),
                            FechaDesde = reader.GetDateTime(1),
                            FechaHasta = reader.GetDateTime(2),
                            MontoAlquiler = reader.GetDecimal(3),
                            IdInmueble = reader.GetInt32(4),
                            IdInquilino = reader.GetInt32(5),
                            Inmueble = new Inmueble
                            {
                                Direccion = reader.GetString(6),
                            },
                            Inquilino = new Inquilino
                            {
                                Nombre = reader.GetString(7),
                                Apellido = reader.GetString(8),
                            }
                        };
                    }
                    connection.Close();
                }
            }
            return c;
        }

    }
}
