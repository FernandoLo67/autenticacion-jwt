package com.fernando.auth.password;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class HashContrasenaTest {

    private static final String CONTRASENA = "contrasena-segura";

    @Test
    void unaContrasenaCoincideConSuPropioHash() {
        assertTrue(HashContrasena.coincide(CONTRASENA, HashContrasena.hashear(CONTRASENA)));
    }

    @Test
    void unaContrasenaDistintaNoCoincide() {
        String hash = HashContrasena.hashear(CONTRASENA);

        assertFalse(HashContrasena.coincide("otra-contrasena", hash));
        assertFalse(HashContrasena.coincide(CONTRASENA + "x", hash));
        assertFalse(HashContrasena.coincide("", hash));
    }

    @Test
    void laMismaContrasenaProduceHashesDistintos() {
        // Si dos hashes de la misma clave fueran iguales, no habria sal.
        String uno = HashContrasena.hashear(CONTRASENA);
        String otro = HashContrasena.hashear(CONTRASENA);

        assertNotEquals(uno, otro, "Cada hash debe llevar su propia sal aleatoria");
        assertTrue(HashContrasena.coincide(CONTRASENA, uno));
        assertTrue(HashContrasena.coincide(CONTRASENA, otro));
    }

    @Test
    void elHashNoContieneLaContrasenaEnClaro() {
        assertFalse(HashContrasena.hashear(CONTRASENA).contains(CONTRASENA));
    }

    @Test
    void elFormatoGuardadoLlevaIteracionesSalYHash() {
        String[] partes = HashContrasena.hashear(CONTRASENA).split(":");

        assertEquals(3, partes.length);
        assertEquals(HashContrasena.ITERACIONES, Integer.parseInt(partes[0]));
        assertEquals(HashContrasena.BYTES_SAL,
                java.util.Base64.getDecoder().decode(partes[1]).length);
        assertEquals(HashContrasena.BITS_CLAVE / 8,
                java.util.Base64.getDecoder().decode(partes[2]).length);
    }

    @Test
    void unaContrasenaCortaEsRechazada() {
        assertThrows(IllegalArgumentException.class, () -> HashContrasena.hashear("corta"));
        assertThrows(IllegalArgumentException.class, () -> HashContrasena.hashear(null));
    }

    @Test
    void unHashConFormatoInvalidoEsRechazado() {
        assertThrows(IllegalArgumentException.class,
                () -> HashContrasena.coincide(CONTRASENA, "esto-no-es-un-hash"));
        assertThrows(IllegalArgumentException.class,
                () -> HashContrasena.coincide(CONTRASENA, "abc:def:no-es-base64!!"));
    }

    @Test
    void valoresNulosNoCoincidenNiRevientan() {
        assertFalse(HashContrasena.coincide(null, HashContrasena.hashear(CONTRASENA)));
        assertFalse(HashContrasena.coincide(CONTRASENA, null));
    }

    @Test
    void detectaLosHashesConMenosIteracionesDeLasActuales() {
        assertFalse(HashContrasena.necesitaRehash(HashContrasena.hashear(CONTRASENA)));
        assertTrue(HashContrasena.necesitaRehash("1000:c2Fs:aGFzaA=="));
        assertTrue(HashContrasena.necesitaRehash("formato-viejo"));
    }
}
