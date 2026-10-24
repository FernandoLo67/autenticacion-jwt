package com.fernando.auth.password;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Comprueba que una contrasena cumpla requisitos minimos de complejidad
 * antes de que se le calcule el hash.
 *
 * <p>Las reglas son las basicas de OWASP: longitud minima, al menos una
 * mayuscula, una minuscula, un digito y un caracter especial. La
 * validacion devuelve todos los problemas de una vez, no solo el primero,
 * para que el usuario pueda corregir todo en un solo intento.
 */
public final class ValidadorContrasena {

    public static final int LONGITUD_MINIMA = 8;
    public static final int LONGITUD_MAXIMA = 128;

    private ValidadorContrasena() {
    }

    public static List<String> validar(String contrasena) {
        if (contrasena == null) {
            return List.of("La contrasena no puede ser nula");
        }

        List<String> problemas = new ArrayList<>();

        if (contrasena.length() < LONGITUD_MINIMA) {
            problemas.add("Debe tener al menos " + LONGITUD_MINIMA + " caracteres");
        }
        if (contrasena.length() > LONGITUD_MAXIMA) {
            problemas.add("No puede exceder " + LONGITUD_MAXIMA + " caracteres");
        }
        if (contrasena.chars().noneMatch(Character::isUpperCase)) {
            problemas.add("Debe incluir al menos una mayuscula");
        }
        if (contrasena.chars().noneMatch(Character::isLowerCase)) {
            problemas.add("Debe incluir al menos una minuscula");
        }
        if (contrasena.chars().noneMatch(Character::isDigit)) {
            problemas.add("Debe incluir al menos un digito");
        }
        if (contrasena.chars().allMatch(c -> Character.isLetterOrDigit(c))) {
            problemas.add("Debe incluir al menos un caracter especial");
        }

        return Collections.unmodifiableList(problemas);
    }

    public static boolean esValida(String contrasena) {
        return validar(contrasena).isEmpty();
    }
}
