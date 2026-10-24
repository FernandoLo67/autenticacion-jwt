package com.fernando.auth.servicio;

import com.fernando.auth.jwt.*;
import com.fernando.auth.password.HashContrasena;
import com.fernando.auth.password.ValidadorContrasena;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

/**
 * Registro, inicio de sesion, refresco y autorizacion por roles.
 *
 * Se emiten dos tokens: uno de acceso, de vida corta, que viaja en cada
 * peticion, y uno de refresco, de vida larga, que solo sirve para pedir un
 * token de acceso nuevo. Si roban el de acceso, caduca pronto; el de refresco
 * puede revocarse.
 */
public class ServicioAutenticacion {

    public static final Duration VIDA_TOKEN_ACCESO = Duration.ofMinutes(15);
    public static final Duration VIDA_TOKEN_REFRESCO = Duration.ofDays(7);
    public static final String EMISOR = "fernando-auth";
    public static final int MAX_INTENTOS_FALLIDOS = 5;

    private final Map<String, Usuario> usuarios = new ConcurrentHashMap<>();
    private final Map<String, Integer> intentosFallidos = new ConcurrentHashMap<>();
    /** jti de los tokens de refresco revocados (una lista negra). */
    private final Set<String> refrescosRevocados = ConcurrentHashMap.newKeySet();

    private final EmisorJwt emisor;
    private final Supplier<Instant> reloj;

    public ServicioAutenticacion(EmisorJwt emisor, Supplier<Instant> reloj) {
        this.emisor = Objects.requireNonNull(emisor);
        this.reloj = Objects.requireNonNull(reloj);
    }

    public Usuario registrar(String usuario, String email, String contrasena, Set<Rol> roles) {
        String clave = usuario.trim().toLowerCase();
        if (usuarios.containsKey(clave)) {
            throw new AutenticacionException("El usuario '" + clave + "' ya existe");
        }
        List<String> problemas = ValidadorContrasena.validar(contrasena);
        if (!problemas.isEmpty()) {
            throw new AutenticacionException(
                    "Contrasena no cumple los requisitos: " + String.join("; ", problemas));
        }
        Usuario nuevo = new Usuario(usuario, email, HashContrasena.hashear(contrasena), roles);
        usuarios.put(clave, nuevo);
        return nuevo;
    }

    public ParDeTokens iniciarSesion(String usuario, String contrasena) {
        String clave = usuario == null ? "" : usuario.trim().toLowerCase();
        Usuario encontrado = usuarios.get(clave);

        // Mismo mensaje si el usuario no existe o si la contrasena esta mal:
        // decir cual de las dos fallo le regalaria al atacante la lista de usuarios.
        if (encontrado == null || !HashContrasena.coincide(contrasena, encontrado.getHashContrasena())) {
            if (encontrado != null) {
                registrarIntentoFallido(clave);
            }
            throw new AutenticacionException("Usuario o contrasena incorrectos");
        }
        if (!encontrado.estaActivo()) {
            throw new AutenticacionException("La cuenta esta bloqueada");
        }
        if (intentosFallidos.getOrDefault(clave, 0) >= MAX_INTENTOS_FALLIDOS) {
            throw new AutenticacionException("Demasiados intentos fallidos; la cuenta quedo bloqueada");
        }

        intentosFallidos.remove(clave);
        return emitirPar(encontrado);
    }

    private void registrarIntentoFallido(String usuario) {
        int fallos = intentosFallidos.merge(usuario, 1, Integer::sum);
        if (fallos >= MAX_INTENTOS_FALLIDOS) {
            Optional.ofNullable(usuarios.get(usuario)).ifPresent(Usuario::desactivar);
        }
    }

    private ParDeTokens emitirPar(Usuario usuario) {
        Instant ahora = reloj.get();

        String acceso = emisor.emitir(Claims.constructor()
                .sujeto(usuario.getUsuario())
                .emisor(EMISOR)
                .idToken(UUID.randomUUID().toString())
                .roles(usuario.nombresDeRoles())
                .con("tipo", "acceso")
                .emitidoEn(ahora)
                .expiracion(ahora.plus(VIDA_TOKEN_ACCESO))
                .construir());

        String refresco = emisor.emitir(Claims.constructor()
                .sujeto(usuario.getUsuario())
                .emisor(EMISOR)
                .idToken(UUID.randomUUID().toString())
                .con("tipo", "refresco")
                .emitidoEn(ahora)
                .expiracion(ahora.plus(VIDA_TOKEN_REFRESCO))
                .construir());

        return new ParDeTokens(acceso, refresco);
    }

    /** Cambia un token de refresco valido por un par nuevo, revocando el anterior. */
    public ParDeTokens refrescar(String tokenDeRefresco) {
        Claims claims = emisor.verificar(tokenDeRefresco);

        if (!"refresco".equals(claims.texto("tipo"))) {
            throw new AutenticacionException("Se esperaba un token de refresco, no uno de acceso");
        }
        if (refrescosRevocados.contains(claims.idToken())) {
            throw new AutenticacionException("Este token de refresco ya fue usado o revocado");
        }

        Usuario usuario = usuarios.get(claims.sujeto());
        if (usuario == null || !usuario.estaActivo()) {
            throw new AutenticacionException("La cuenta ya no esta disponible");
        }

        // Rotacion: el refresco usado se invalida para que no se pueda reutilizar.
        refrescosRevocados.add(claims.idToken());
        return emitirPar(usuario);
    }

    public void cerrarSesion(String tokenDeRefresco) {
        try {
            refrescosRevocados.add(emisor.leerSinVerificar(tokenDeRefresco).idToken());
        } catch (JwtException e) {
            // Cerrar sesion con un token ilegible no es un error para el usuario.
        }
    }

    /** Valida el token de acceso y devuelve sus claims. */
    public Claims autenticar(String tokenDeAcceso) {
        Claims claims = emisor.verificar(tokenDeAcceso);
        if (!"acceso".equals(claims.texto("tipo"))) {
            throw new AutenticacionException("Se esperaba un token de acceso");
        }
        Usuario usuario = usuarios.get(claims.sujeto());
        if (usuario == null || !usuario.estaActivo()) {
            throw new AutenticacionException("La cuenta ya no esta disponible");
        }
        return claims;
    }

    /** Valida el token y ademas exige uno de los roles indicados. */
    public Claims autorizar(String tokenDeAcceso, Rol... rolesPermitidos) {
        Claims claims = autenticar(tokenDeAcceso);
        for (Rol rol : rolesPermitidos) {
            if (claims.tieneRol(rol.name())) {
                return claims;
            }
        }
        throw new AutenticacionException(
                "Permisos insuficientes: se requiere " + Arrays.toString(rolesPermitidos)
                        + " y el token trae " + claims.roles());
    }

    public Optional<Usuario> buscarUsuario(String usuario) {
        return Optional.ofNullable(usuarios.get(usuario.trim().toLowerCase()));
    }

    public int intentosFallidosDe(String usuario) {
        return intentosFallidos.getOrDefault(usuario.trim().toLowerCase(), 0);
    }

    public Collection<Usuario> listarUsuarios() {
        return List.copyOf(usuarios.values());
    }
}
