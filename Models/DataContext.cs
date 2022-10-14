using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;


namespace InmobiliariaEfler.Models
{
    public class DataContext : DbContext
    {
        public DataContext(DbContextOptions<DataContext> options) : base(options)
        {

        }
        public DbSet<Propietario> Propietario { get; set; }
        public DbSet<Inquilino> Inquilinos { get; set; }
        public DbSet<Inmueble> Inmuebles { get; set; }

    }
}