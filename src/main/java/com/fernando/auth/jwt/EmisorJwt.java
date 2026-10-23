package com.fernando.auth.jwt;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Supplier;

/**
 * Emite y verifica JSON Web Tokens firmados con HMAC, implementado desde cero
 * sobre javax.crypto (RFC 7515 y RFC 7519).
 *
 * Un token es:  base64url(encabezado) . base64url(contenido) . base64url(firma)
 * y la firma es el HMAC de los dos primeros segmentos unidos por un punto.
 */
public class EmisorJwt {

    /** Margen de tolerancia para desfases de reloj entre servidores. */
    public static final Duration TOLERANCIA_RELOJ = Duration.ofSeconds(30);

    private static final int LONGITUD_MINIMA_CLAVE = 32;

    private final byte[] clave;
    private final Algoritmo algoritmo;
    private final Supplier<Instant> reloj;

    public EmisorJwt(String clave, Algoritmo algoritmo, Supplier<Instant> reloj) {
        Objects.requireNonNull(clave, "La clave es obligatoria");
        if (clave.getBytes(StandardCharsets.UTF_8).length < LONGITUD_MINIMA_CLAVE) {
            throw new IllegalArgumentException(
                    "La clave debe tener al menos " + LONGITUD_MINIMA_CLAVE + " bytes");
        }
        this.clave = clave.getBytes(StandardCharsets.UTF_8);
        this.algoritmo = Objects.requireNonNull(algoritmo);
        this.reloj = Objects.requireNonNull(reloj);
    }

    public Algoritmo getAlgoritmo() {
        return algoritmo;
    }

    /** Firma los claims tal como vienen. */
    public String emitir(Claims claims) {
        Map<String, Object> encabezado = new LinkedHashMap<>();
        encabezado.put("alg", algoritmo.name());
        encabezado.put("typ", "JWT");

        String encabezadoB64 = Base64Url.codificar(Json.escribir(encabezado));
        String contenidoB64 = Base64Url.codificar(Json.escribir(claims.comoMapa()));
        String aFirmar = encabezadoB64 + "." + contenidoB64;

        return aFirmar + "." + Base64Url.codificar(firmar(aFirmar));
    }

    /** Atajo: agrega iat y exp automaticamente a partir del reloj. */
    public String emitir(Claims.Constructor constructor, Duration validez) {
        Instant ahora = reloj.get();
        return emitir(constructor
                .emitidoEn(ahora)
                .expiracion(ahora.plus(validez))
                .construir());
    }

    /**
     * Verifica firma y vigencia. Lanza si algo no cuadra; devuelve los claims si todo esta bien.
     */
    public Claims verificar(String token) {
        if (token == null || token.isBlank()) {
            throw new TokenMalFormadoException("El token esta vacio");
        }
        String[] partes = token.split("\\.", -1);
        if (partes.length != 3) {
            throw new TokenMalFormadoException(
                    "Un JWT tiene exactamente 3 segmentos y este tiene " + partes.length);
        }

        Map<String, Object> encabezado = Json.parsearObjeto(Base64Url.decodificarTexto(partes[0]));
        Algoritmo algoritmoDelToken = Algoritmo.desde(
                encabezado.get("alg") == null ? null : String.valueOf(encabezado.get("alg")));

        // Sustitucion de algoritmo: el token no decide con que se verifica.
        // El algoritmo lo fija el servidor; si el token trae otro, se rechaza.
        if (algoritmoDelToken != algoritmo) {
            throw new FirmaInvalidaException(
                    "El token declara " + algoritmoDelToken + " pero este emisor solo acepta " + algoritmo);
        }

        byte[] firmaEsperada = firmar(partes[0] + "." + partes[1]);
        byte[] firmaRecibida = Base64Url.decodificar(partes[2]);

        // Comparacion en tiempo constante: evita filtrar informacion por
        // cuanto tarda en fallar la comparacion byte a byte.
        if (!MessageDigest.isEqual(firmaEsperada, firmaRecibida)) {
            throw new FirmaInvalidaException("La firma del token no es valida");
        }

        Claims claims = new Claims(Json.parsearObjeto(Base64Url.decodificarTexto(partes[1])));
        validarVigencia(claims);
        return claims;
    }

    /** Como verificar, pero devolviendo true/false en vez de lanzar. */
    public boolean esValido(String token) {
        try {
            verificar(token);
            return true;
        } catch (JwtException e) {
            return false;
        }
    }

    /** Lee los claims SIN comprobar la firma. Solo para diagnostico, nunca para autorizar. */
    public Claims leerSinVerificar(String token) {
        String[] partes = token.split("\\.", -1);
        if (partes.length != 3) {
            throw new TokenMalFormadoException("Un JWT tiene exactamente 3 segmentos");
        }
        return new Claims(Json.parsearObjeto(Base64Url.decodificarTexto(partes[1])));
    }

    private void validarVigencia(Claims claims) {
        Instant ahora = reloj.get();

        Instant expiracion = claims.expiracion();
        if (expiracion != null && ahora.isAfter(expiracion.plus(TOLERANCIA_RELOJ))) {
            throw new TokenExpiradoException(expiracion);
        }

        Instant noAntesDe = claims.noAntesDe();
        if (noAntesDe != null && ahora.plus(TOLERANCIA_RELOJ).isBefore(noAntesDe)) {
            throw new JwtException("El token aun no es valido; empieza a serlo el " + noAntesDe);
        }
    }

    private byte[] firmar(String datos) {
        try {
            Mac mac = Mac.getInstance(algoritmo.getNombreJca());
            mac.init(new SecretKeySpec(clave, algoritmo.getNombreJca()));
            return mac.doFinal(datos.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("No se pudo calcular el HMAC: " + e.getMessage(), e);
        }
    }
}
