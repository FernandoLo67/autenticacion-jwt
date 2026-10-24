package com.fernando.auth.password;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ValidadorContrasenaTest {

    @Test
    void contrasenaFuerteNoTieneProblemas() {
        assertTrue(ValidadorContrasena.esValida("Abc12345!"));
        assertTrue(ValidadorContrasena.validar("Abc12345!").isEmpty());
    }

    @Test
    void contraseNulaSeRechaza() {
        List<String> problemas = ValidadorContrasena.validar(null);
        assertEquals(1, problemas.size());
        assertTrue(problemas.get(0).contains("nula"));
    }

    @Test
    void demasiadoCortaSeRechaza() {
        List<String> problemas = ValidadorContrasena.validar("Ab1!");
        assertTrue(problemas.stream().anyMatch(p -> p.contains("8 caracteres")));
    }

    @Test
    void demasiadoLargaSeRechaza() {
        String larga = "Aa1!" + "x".repeat(126);
        List<String> problemas = ValidadorContrasena.validar(larga);
        assertTrue(problemas.stream().anyMatch(p -> p.contains("128")));
    }

    @Test
    void sinMayusculaSeRechaza() {
        List<String> problemas = ValidadorContrasena.validar("abc12345!");
        assertTrue(problemas.stream().anyMatch(p -> p.contains("mayuscula")));
    }

    @Test
    void sinMinusculaSeRechaza() {
        List<String> problemas = ValidadorContrasena.validar("ABC12345!");
        assertTrue(problemas.stream().anyMatch(p -> p.contains("minuscula")));
    }

    @Test
    void sinDigitoSeRechaza() {
        List<String> problemas = ValidadorContrasena.validar("Abcdefgh!");
        assertTrue(problemas.stream().anyMatch(p -> p.contains("digito")));
    }

    @Test
    void sinCaracterEspecialSeRechaza() {
        List<String> problemas = ValidadorContrasena.validar("Abc12345x");
        assertTrue(problemas.stream().anyMatch(p -> p.contains("especial")));
    }

    @Test
    void devuelveTodosLosProblemasDeUnaVez() {
        List<String> problemas = ValidadorContrasena.validar("abc");
        assertTrue(problemas.size() >= 3,
                "Una contrasena con multiples fallos debe reportar todos, no solo el primero");
    }

    @Test
    void listaDevueltaNoEsModificable() {
        List<String> problemas = ValidadorContrasena.validar("debil");
        assertThrows(UnsupportedOperationException.class, () -> problemas.add("trampa"));
    }
}
