using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using InmobiliariaEfler.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;



namespace InmobiliariaEfler.Api
{
    [Route("api/[controller]")]
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    [ApiController]
    public class PropietariosController : ControllerBase//
    {
        private readonly DataContext contexto;
        private readonly IConfiguration config;

        public PropietariosController(DataContext contexto, IConfiguration config)
        {
            this.contexto = contexto;
            this.config = config;
        }
        // GET: api/<controller>
        [HttpGet]
        public async Task<ActionResult<Propietario>> Get()
        {
            try
            {
                var usuario = User.Identity.Name;
                return await contexto.Propietario.SingleOrDefaultAsync(x => x.Email == usuario);
                //return Ok(await contexto.Propietario.ToListAsync());
            }
            catch (Exception ex)
            {
                return BadRequest(ex);
            }
        }

        // GET api/<controller>/5
        [HttpGet("{id}")]
        public async Task<IActionResult> Get(int id)
        {
            try
            {
                var entidad = await contexto.Propietario.SingleOrDefaultAsync(x => x.Id == id);
                return entidad != null ? Ok(entidad) : NotFound();
            }
            catch (Exception ex)
            {
                return BadRequest(ex);
            }
        }

        // GET api/<controller>/GetAll
        [HttpGet("GetAll")]
        public async Task<IActionResult> GetAll()
        {
            try
            {
                return Ok(await contexto.Propietario.ToListAsync());
            }
            catch (Exception ex)
            {
                return BadRequest(ex);
            }
        }

        // POST api/<controller>/login
        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login([FromForm] UsuarioLogin usuarioLogin)
        {
            try
            {
                string hashed = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                    password: usuarioLogin.Password,
                    salt: System.Text.Encoding.ASCII.GetBytes(config["Salt"]),
                    prf: KeyDerivationPrf.HMACSHA1,
                    iterationCount: 1000,
                    numBytesRequested: 256 / 8));

                var p = await contexto.Propietario.FirstOrDefaultAsync(x => x.Email == usuarioLogin.Email);
                if (p == null || p.Password != hashed)
                {
                    return BadRequest("Nombre de usuario o clave incorrecta");
                }
                else
                {
                    var key = new SymmetricSecurityKey(
                        System.Text.Encoding.ASCII.GetBytes(config["TokenAuthentication:SecretKey"]));
                    var credenciales = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
                    var claims = new List<Claim>
                    {
                        new Claim(ClaimTypes.Name, p.Email),
                        new Claim("FullName", p.Nombre + " " + p.Apellido),
                        new Claim(ClaimTypes.Role, "Propietario"),
                    };

                    var token = new JwtSecurityToken(
                        issuer: config["TokenAuthentication:Issuer"],
                        audience: config["TokenAuthentication:Audience"],
                        claims: claims,
                        expires: DateTime.Now.AddMinutes(60),
                        signingCredentials: credenciales
                    );
                    return Ok(new JwtSecurityTokenHandler().WriteToken(token));
                }
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
        /*
                // POST api/<controller>
                [HttpPost]
                public async Task<IActionResult> Post([FromForm] Propietario entidad)
                {
                    try
                    {
                        if (ModelState.IsValid)
                        {
                            await contexto.Propietario.AddAsync(entidad);
                            contexto.SaveChanges();
                            return CreatedAtAction(nameof(Get), new { id = entidad.IdPropietario }, entidad);
                        }
                        return BadRequest();
                    }
                    catch (Exception ex)
                    {
                        return BadRequest(ex);
                    }
                }

                // PUT api/<controller>/5
                [HttpPut("{id}")]
                public async Task<IActionResult> Put(int id, [FromForm] Propietario entidad)
                {
                    try
                    {
                        if (ModelState.IsValid)
                        {
                            entidad.Id = id;
                            Propietario original = await contexto.Propietario.FindAsync(id);
                            if (String.IsNullOrEmpty(entidad.Clave))
                            {
                                entidad.Clave = original.Clave;
                            }
                            else
                            {
                                entidad.Clave = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                                    password: entidad.Clave,
                                    salt: System.Text.Encoding.ASCII.GetBytes(config["Salt"]),
                                    prf: KeyDerivationPrf.HMACSHA1,
                                    iterationCount: 1000,
                                    numBytesRequested: 256 / 8));
                            }
                            contexto.Propietario.Update(entidad);
                            await contexto.SaveChangesAsync();
                            return Ok(entidad);
                        }
                        return BadRequest();
                    }
                    catch (Exception ex)
                    {
                        return BadRequest(ex);
                    }
                }

                // DELETE api/<controller>/5
                [HttpDelete("{id}")]
                public async Task<IActionResult> Delete(int id)
                {
                    try
                    {
                        if (ModelState.IsValid)
                        {
                            var p = contexto.Propietario.Find(id);
                            if (p == null)
                                return NotFound();
                            contexto.Propietario.Remove(p);
                            contexto.SaveChanges();
                            return Ok(p);
                        }
                        return BadRequest();
                    }
                    catch (Exception ex)
                    {
                        return BadRequest(ex);
                    }
                }

                // GET: api/Propietario/test
                [HttpGet("test")]
                [AllowAnonymous]
                public IActionResult Test()
                {
                    try
                    {
                        return Ok("anduvo");
                    }
                    catch (Exception ex)
                    {
                        return BadRequest(ex);
                    }
                }

                // GET: api/Propietario/test/5
                [HttpGet("test/{codigo}")]
                [AllowAnonymous]
                public IActionResult Code(int codigo)
                {
                    try
                    {
                        //StatusCodes.Status418ImATeapot //constantes con códigos
                        return StatusCode(codigo, new { Mensaje = "Anduvo", Error = false });
                    }
                    catch (Exception ex)
                    {
                        return BadRequest(ex);
                    }
                }*/
    }
}