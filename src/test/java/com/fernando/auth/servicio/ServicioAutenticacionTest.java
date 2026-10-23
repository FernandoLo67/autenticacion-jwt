package com.fernando.auth.servicio;

import com.fernando.auth.jwt.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class ServicioAutenticacionTest {

    private static final String CLAVE = "una-clave-secreta-de-al-menos-32-bytes-para-hmac";

    private Instant[] ahora;
    private ServicioAutenticacion auth;

    @BeforeEach
    void prepararServicio() {
        ahora = new Instant[]{Instant.parse("2026-08-24T10:00:00Z")};
        EmisorJwt emisor = new EmisorJwt(CLAVE, Algoritmo.HS256, () -> ahora[0]);
        auth = new ServicioAutenticacion(emisor, () -> ahora[0]);

        auth.registrar("daniel", "daniel@ejemplo.com", "contrasena-segura", Set.of(Rol.ADMIN));
        auth.registrar("ana", "ana@ejemplo.com", "otra-contrasena", Set.of(Rol.USUARIO));
    }

    @Test
    void iniciarSesionDevuelveUnParDeTokens() {
        ParDeTokens tokens = auth.iniciarSesion("daniel", "contrasena-segura");

        assertNotNull(tokens.tokenDeAcceso());
        assertNotNull(tokens.tokenDeRefresco());
        assertNotEquals(tokens.tokenDeAcceso(), tokens.tokenDeRefresco());
    }

    @Test
    void elNombreDeUsuarioNoDistingueMayusculas() {
        assertDoesNotThrow(() -> auth.iniciarSesion("DANIEL", "contrasena-segura"));
    }

    @Test
    void unaContrasenaIncorrectaEsRechazada() {
        assertThrows(AutenticacionException.class, () -> auth.iniciarSesion("daniel", "incorrecta"));
    }

    @Test
    void elMensajeDeErrorNoRevelaSiElUsuarioExiste() {
        String conUsuarioReal = assertThrows(AutenticacionException.class,
                () -> auth.iniciarSesion("daniel", "incorrecta")).getMessage();
        String conUsuarioFalso = assertThrows(AutenticacionException.class,
                () -> auth.iniciarSesion("no-existe", "loquesea")).getMessage();

        assertEquals(conUsuarioReal, conUsuarioFalso,
                "Distinguirlos le daria al atacante la lista de usuarios validos");
    }

    @Test
    void noSePuedeRegistrarDosVecesElMismoUsuario() {
        assertThrows(AutenticacionException.class,
                () -> auth.registrar("daniel", "otro@ejemplo.com", "contrasena-segura", Set.of()));
    }

    @Test
    void elTokenDeAccesoLlevaSujetoYRoles() {
        Claims claims = auth.autenticar(auth.iniciarSesion("daniel", "contrasena-segura").tokenDeAcceso());

        assertEquals("daniel", claims.sujeto());
        assertEquals(ServicioAutenticacion.EMISOR, claims.emisor());
        assertTrue(claims.tieneRol("ADMIN"));
        assertEquals("acceso", claims.texto("tipo"));
    }

    @Test
    void autorizarAceptaAlQueTieneElRol() {
        ParDeTokens tokens = auth.iniciarSesion("daniel", "contrasena-segura");
        assertEquals("daniel", auth.autorizar(tokens.tokenDeAcceso(), Rol.ADMIN).sujeto());
    }

    @Test
    void autorizarRechazaAlQueNoTieneElRol() {
        ParDeTokens tokens = auth.iniciarSesion("ana", "otra-contrasena");

        assertThrows(AutenticacionException.class, () -> auth.autorizar(tokens.tokenDeAcceso(), Rol.ADMIN));
        assertDoesNotThrow(() -> auth.autorizar(tokens.tokenDeAcceso(), Rol.USUARIO));
    }

    @Test
    void autorizarAceptaCualquieraDeLosRolesPermitidos() {
        ParDeTokens tokens = auth.iniciarSesion("ana", "otra-contrasena");
        assertDoesNotThrow(() -> auth.autorizar(tokens.tokenDeAcceso(), Rol.ADMIN, Rol.USUARIO));
    }

    @Test
    void unTokenDeRefrescoNoSirveComoTokenDeAcceso() {
        ParDeTokens tokens = auth.iniciarSesion("daniel", "contrasena-segura");
        assertThrows(AutenticacionException.class, () -> auth.autenticar(tokens.tokenDeRefresco()));
    }

    @Test
    void unTokenDeAccesoNoSirveParaRefrescar() {
        ParDeTokens tokens = auth.iniciarSesion("daniel", "contrasena-segura");
        assertThrows(AutenticacionException.class, () -> auth.refrescar(tokens.tokenDeAcceso()));
    }

    @Test
    void elTokenDeAccesoCaducaYElDeRefrescoNoTodavia() {
        ParDeTokens tokens = auth.iniciarSesion("daniel", "contrasena-segura");

        ahora[0] = ahora[0].plus(ServicioAutenticacion.VIDA_TOKEN_ACCESO).plusSeconds(60);

        assertThrows(JwtException.class, () -> auth.autenticar(tokens.tokenDeAcceso()));
        assertDoesNotThrow(() -> auth.refrescar(tokens.tokenDeRefresco()));
    }

    @Test
    void refrescarDevuelveTokensNuevosYUsables() {
        ParDeTokens originales = auth.iniciarSesion("daniel", "contrasena-segura");
        ahora[0] = ahora[0].plusSeconds(60);

        ParDeTokens renovados = auth.refrescar(originales.tokenDeRefresco());

        assertNotEquals(originales.tokenDeAcceso(), renovados.tokenDeAcceso());
        assertEquals("daniel", auth.autenticar(renovados.tokenDeAcceso()).sujeto());
    }

    @Test
    void unTokenDeRefrescoNoSePuedeUsarDosVeces() {
        ParDeTokens tokens = auth.iniciarSesion("daniel", "contrasena-segura");
        auth.refrescar(tokens.tokenDeRefresco());

        assertThrows(AutenticacionException.class, () -> auth.refrescar(tokens.tokenDeRefresco()),
                "La rotacion debe invalidar el refresco ya usado");
    }

    @Test
    void cerrarSesionInvalidaElTokenDeRefresco() {
        ParDeTokens tokens = auth.iniciarSesion("daniel", "contrasena-segura");
        auth.cerrarSesion(tokens.tokenDeRefresco());

        assertThrows(AutenticacionException.class, () -> auth.refrescar(tokens.tokenDeRefresco()));
    }

    @Test
    void cerrarSesionConUnTokenIlegibleNoRevienta() {
        assertDoesNotThrow(() -> auth.cerrarSesion("basura"));
    }

    @Test
    void trasVariosIntentosFallidosLaCuentaSeBloquea() {
        for (int i = 0; i < ServicioAutenticacion.MAX_INTENTOS_FALLIDOS; i++) {
            assertThrows(AutenticacionException.class, () -> auth.iniciarSesion("daniel", "incorrecta"));
        }
        assertFalse(auth.buscarUsuario("daniel").orElseThrow().estaActivo());
        assertThrows(AutenticacionException.class, () -> auth.iniciarSesion("daniel", "contrasena-segura"));
    }

    @Test
    void unInicioDeSesionExitosoBorraLosIntentosFallidos() {
        assertThrows(AutenticacionException.class, () -> auth.iniciarSesion("daniel", "incorrecta"));
        assertEquals(1, auth.intentosFallidosDe("daniel"));

        auth.iniciarSesion("daniel", "contrasena-segura");

        assertEquals(0, auth.intentosFallidosDe("daniel"));
    }

    @Test
    void unaCuentaDesactivadaNoPuedeAutenticarNiRefrescar() {
        ParDeTokens tokens = auth.iniciarSesion("daniel", "contrasena-segura");
        auth.buscarUsuario("daniel").orElseThrow().desactivar();

        assertThrows(AutenticacionException.class, () -> auth.autenticar(tokens.tokenDeAcceso()));
        assertThrows(AutenticacionException.class, () -> auth.refrescar(tokens.tokenDeRefresco()));
    }

    @Test
    void sinRolesExplicitosSeAsignaUsuarioPorDefecto() {
        Usuario beto = auth.registrar("beto", "beto@ejemplo.com", "contrasena-larga", Set.of());
        assertEquals(Set.of(Rol.USUARIO), beto.getRoles());
    }

    @Test
    void unTokenDeOtroEmisorNoEsAceptado() {
        EmisorJwt intruso = new EmisorJwt(
                "clave-del-atacante-de-al-menos-32-bytes-de-largo", Algoritmo.HS256, () -> ahora[0]);
        String falso = intruso.emitir(Claims.constructor()
                .sujeto("daniel").roles(java.util.List.of("ADMIN")).con("tipo", "acceso")
                .expiracion(ahora[0].plusSeconds(600)).construir());

        assertThrows(FirmaInvalidaException.class, () -> auth.autenticar(falso));
    }
}
