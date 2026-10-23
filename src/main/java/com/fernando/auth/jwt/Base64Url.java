package com.fernando.auth.jwt;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Base64 en su variante "URL-safe y sin relleno", que es la que exige
 * el estandar JWT (RFC 7515): usa '-' y '_' en vez de '+' y '/', y no
 * lleva los '=' del final.
 */
public final class Base64Url {

    private static final Base64.Encoder CODIFICADOR = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder DECODIFICADOR = Base64.getUrlDecoder();

    private Base64Url() {
    }

    public static String codificar(byte[] datos) {
        return CODIFICADOR.encodeToString(datos);
    }

    public static String codificar(String texto) {
        return codificar(texto.getBytes(StandardCharsets.UTF_8));
    }

    public static byte[] decodificar(String texto) {
        try {
            return DECODIFICADOR.decode(texto);
        } catch (IllegalArgumentException e) {
            throw new TokenMalFormadoException("El segmento no es Base64Url valido: " + e.getMessage());
        }
    }

    public static String decodificarTexto(String texto) {
        return new String(decodificar(texto), StandardCharsets.UTF_8);
    }
}
