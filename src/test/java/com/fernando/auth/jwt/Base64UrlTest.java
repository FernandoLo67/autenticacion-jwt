package com.fernando.auth.jwt;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class Base64UrlTest {

    @Test
    void codificarYDecodificarDevuelveElOriginal() {
        String original = "{\"sub\":\"daniel\",\"roles\":[\"ADMIN\"]}";
        assertEquals(original, Base64Url.decodificarTexto(Base64Url.codificar(original)));
    }

    @Test
    void nuncaAgregaRelleno() {
        for (String entrada : new String[]{"a", "ab", "abc", "abcd", "abcde"}) {
            assertFalse(Base64Url.codificar(entrada).contains("="),
                    "'" + entrada + "' no deberia llevar relleno");
        }
    }

    @Test
    void usaElAlfabetoSeguroParaUrls() {
        // Estos bytes producen '+' y '/' en Base64 clasico.
        byte[] datos = {(byte) 0xFB, (byte) 0xFF, (byte) 0xBE};
        String codificado = Base64Url.codificar(datos);

        assertFalse(codificado.contains("+"));
        assertFalse(codificado.contains("/"));
        assertArrayEquals(datos, Base64Url.decodificar(codificado));
    }

    @Test
    void conservaLosAcentosYCaracteresNoAscii() {
        String original = "Mañana será un día soleado";
        assertEquals(original, Base64Url.decodificarTexto(Base64Url.codificar(original)));
    }

    @Test
    void unaEntradaVaciaSeCodificaComoCadenaVacia() {
        assertEquals("", Base64Url.codificar(new byte[0]));
        assertEquals(0, Base64Url.decodificar("").length);
    }

    @Test
    void codificaBytesArbitrariosSinPerderInformacion() {
        byte[] datos = new byte[256];
        for (int i = 0; i < 256; i++) {
            datos[i] = (byte) i;
        }
        assertArrayEquals(datos, Base64Url.decodificar(Base64Url.codificar(datos)));
    }

    @Test
    void unTextoQueNoEsBase64EsRechazado() {
        assertThrows(TokenMalFormadoException.class, () -> Base64Url.decodificar("no es base64 !!!"));
    }

    @Test
    void codificaDesdeBytesUtf8() {
        assertEquals(Base64Url.codificar("hola"),
                Base64Url.codificar("hola".getBytes(StandardCharsets.UTF_8)));
    }
}
