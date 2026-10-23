package com.fernando.auth.jwt;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class EmisorJwtTest {

    private static final String CLAVE = "una-clave-secreta-de-al-menos-32-bytes-para-hmac";
    private static final String OTRA_CLAVE = "otra-clave-distinta-de-al-menos-32-bytes-aqui";

    private Instant[] ahora;
    private EmisorJwt emisor;

    @BeforeEach
    void prepararEmisor() {
        ahora = new Instant[]{Instant.parse("2026-08-24T10:00:00Z")};
        emisor = new EmisorJwt(CLAVE, Algoritmo.HS256, () -> ahora[0]);
    }

    private String tokenDePrueba() {
        return emisor.emitir(Claims.constructor()
                .sujeto("daniel")
                .emisor("pruebas")
                .roles(List.of("ADMIN", "USUARIO")), Duration.ofMinutes(15));
    }

    @Test
    void unTokenTieneExactamenteTresSegmentos() {
        assertEquals(3, tokenDePrueba().split("\\.").length);
    }

    @Test
    void elEncabezadoDeclaraElAlgoritmoYElTipo() {
        String encabezado = Base64Url.decodificarTexto(tokenDePrueba().split("\\.")[0]);

        assertTrue(encabezado.contains("\"alg\":\"HS256\""));
        assertTrue(encabezado.contains("\"typ\":\"JWT\""));
    }

    @Test
    void losSegmentosNoLlevanRellenoDeBase64() {
        for (String parte : tokenDePrueba().split("\\.")) {
            assertFalse(parte.contains("="), "Base64Url de JWT no lleva '='");
            assertFalse(parte.contains("+"), "Base64Url usa '-' en vez de '+'");
            assertFalse(parte.contains("/"), "Base64Url usa '_' en vez de '/'");
        }
    }

    @Test
    void verificarDevuelveLosClaimsOriginales() {
        Claims claims = emisor.verificar(tokenDePrueba());

        assertEquals("daniel", claims.sujeto());
        assertEquals("pruebas", claims.emisor());
        assertEquals(Set.of("ADMIN", "USUARIO"), claims.roles());
        assertTrue(claims.tieneRol("ADMIN"));
        assertFalse(claims.tieneRol("EDITOR"));
    }

    @Test
    void emitirConValidezFijaIatYExp() {
        Claims claims = emisor.verificar(tokenDePrueba());

        assertEquals(ahora[0].getEpochSecond(), claims.emitidoEn().getEpochSecond());
        assertEquals(ahora[0].plus(Duration.ofMinutes(15)).getEpochSecond(),
                claims.expiracion().getEpochSecond());
    }

    @Test
    void unContenidoManipuladoInvalidaLaFirma() {
        String[] partes = tokenDePrueba().split("\\.");
        String contenidoFalso = Base64Url.codificar("{\"sub\":\"atacante\",\"roles\":[\"ADMIN\"]}");
        String manipulado = partes[0] + "." + contenidoFalso + "." + partes[2];

        assertThrows(FirmaInvalidaException.class, () -> emisor.verificar(manipulado));
    }

    @Test
    void unaFirmaDeOtraClaveEsRechazada() {
        EmisorJwt intruso = new EmisorJwt(OTRA_CLAVE, Algoritmo.HS256, () -> ahora[0]);
        String tokenDelIntruso = intruso.emitir(
                Claims.constructor().sujeto("atacante").roles(List.of("ADMIN")), Duration.ofMinutes(15));

        assertThrows(FirmaInvalidaException.class, () -> emisor.verificar(tokenDelIntruso));
    }

    @Test
    void elAlgoritmoNoneEsRechazado() {
        // El ataque clasico: cambiar el encabezado a alg:none y borrar la firma.
        String encabezado = Base64Url.codificar("{\"alg\":\"none\",\"typ\":\"JWT\"}");
        String contenido = Base64Url.codificar("{\"sub\":\"atacante\",\"roles\":[\"ADMIN\"]}");

        assertThrows(FirmaInvalidaException.class, () -> emisor.verificar(encabezado + "." + contenido + "."));
    }

    @Test
    void unTokenFirmadoConOtroAlgoritmoEsRechazado() {
        // Sustitucion de algoritmo: el token no decide como se verifica.
        EmisorJwt emisor512 = new EmisorJwt(CLAVE, Algoritmo.HS512, () -> ahora[0]);
        String tokenHs512 = emisor512.emitir(Claims.constructor().sujeto("daniel"), Duration.ofMinutes(5));

        FirmaInvalidaException e = assertThrows(FirmaInvalidaException.class,
                () -> emisor.verificar(tokenHs512));
        assertTrue(e.getMessage().contains("HS512"));
    }

    @Test
    void unAlgoritmoDesconocidoEsRechazado() {
        String encabezado = Base64Url.codificar("{\"alg\":\"XY999\",\"typ\":\"JWT\"}");
        String contenido = Base64Url.codificar("{\"sub\":\"x\"}");

        assertThrows(FirmaInvalidaException.class,
                () -> emisor.verificar(encabezado + "." + contenido + ".firma"));
    }

    @Test
    void unTokenExpiradoEsRechazado() {
        String token = emisor.emitir(Claims.constructor().sujeto("daniel"), Duration.ofMinutes(15));

        ahora[0] = ahora[0].plus(Duration.ofMinutes(16));

        assertThrows(TokenExpiradoException.class, () -> emisor.verificar(token));
        assertFalse(emisor.esValido(token));
    }

    @Test
    void justoAntesDeExpirarSigueSiendoValido() {
        String token = emisor.emitir(Claims.constructor().sujeto("daniel"), Duration.ofMinutes(15));
        ahora[0] = ahora[0].plus(Duration.ofMinutes(14));
        assertTrue(emisor.esValido(token));
    }

    @Test
    void laToleranciaDeRelojPermiteUnPequenoDesfase() {
        String token = emisor.emitir(Claims.constructor().sujeto("daniel"), Duration.ofMinutes(15));

        // 10 segundos pasado el vencimiento, dentro de la tolerancia de 30s
        ahora[0] = ahora[0].plus(Duration.ofMinutes(15)).plusSeconds(10);
        assertTrue(emisor.esValido(token));

        ahora[0] = ahora[0].plusSeconds(60);
        assertFalse(emisor.esValido(token));
    }

    @Test
    void unTokenAunNoVigenteEsRechazado() {
        String token = emisor.emitir(Claims.constructor()
                .sujeto("daniel")
                .noAntesDe(ahora[0].plus(Duration.ofHours(1)))
                .expiracion(ahora[0].plus(Duration.ofHours(2)))
                .construir());

        JwtException e = assertThrows(JwtException.class, () -> emisor.verificar(token));
        assertTrue(e.getMessage().contains("aun no es valido"));
    }

    @Test
    void unTokenSinExpiracionNoCaduca() {
        String token = emisor.emitir(Claims.constructor().sujeto("daniel").construir());
        ahora[0] = ahora[0].plus(Duration.ofDays(3650));
        assertTrue(emisor.esValido(token));
    }

    @Test
    void unTokenConSegmentosDeMenosEsRechazado() {
        assertThrows(TokenMalFormadoException.class, () -> emisor.verificar("solo.dos"));
        assertThrows(TokenMalFormadoException.class, () -> emisor.verificar("a.b.c.d"));
        assertThrows(TokenMalFormadoException.class, () -> emisor.verificar("   "));
        assertThrows(TokenMalFormadoException.class, () -> emisor.verificar(null));
    }

    @Test
    void unSegmentoQueNoEsBase64EsRechazado() {
        assertThrows(JwtException.class, () -> emisor.verificar("!!!.@@@.###"));
    }

    @Test
    void leerSinVerificarNoComprubaLaFirma() {
        String[] partes = tokenDePrueba().split("\\.");
        String manipulado = partes[0] + "." + Base64Url.codificar("{\"sub\":\"otro\"}") + "." + partes[2];

        assertEquals("otro", emisor.leerSinVerificar(manipulado).sujeto());
        assertThrows(FirmaInvalidaException.class, () -> emisor.verificar(manipulado));
    }

    @Test
    void unaClaveCortaEsRechazada() {
        assertThrows(IllegalArgumentException.class,
                () -> new EmisorJwt("corta", Algoritmo.HS256, () -> ahora[0]));
    }

    @Test
    void losTresAlgoritmosHmacFuncionan() {
        for (Algoritmo algoritmo : Algoritmo.values()) {
            EmisorJwt otro = new EmisorJwt(CLAVE, algoritmo, () -> ahora[0]);
            String token = otro.emitir(Claims.constructor().sujeto("daniel"), Duration.ofMinutes(5));

            assertEquals("daniel", otro.verificar(token).sujeto(), "Fallo con " + algoritmo);
        }
    }

    @Test
    void firmasDeDistintaLongitudSegunElAlgoritmo() {
        int hs256 = Base64Url.decodificar(
                new EmisorJwt(CLAVE, Algoritmo.HS256, () -> ahora[0])
                        .emitir(Claims.constructor().sujeto("x"), Duration.ofMinutes(5))
                        .split("\\.")[2]).length;
        int hs512 = Base64Url.decodificar(
                new EmisorJwt(CLAVE, Algoritmo.HS512, () -> ahora[0])
                        .emitir(Claims.constructor().sujeto("x"), Duration.ofMinutes(5))
                        .split("\\.")[2]).length;

        assertEquals(32, hs256, "HMAC-SHA256 produce 32 bytes");
        assertEquals(64, hs512, "HMAC-SHA512 produce 64 bytes");
    }
}
