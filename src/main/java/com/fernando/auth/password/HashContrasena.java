package com.fernando.auth.password;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Hash de contrasenas con PBKDF2-HMAC-SHA256.
 *
 * Las tres cosas que hay que hacer bien y aqui se hacen:
 *   1. Sal aleatoria distinta por contrasena, para que dos usuarios con la
 *      misma clave no compartan hash y las tablas precalculadas no sirvan.
 *   2. Muchas iteraciones, para que probar contrasenas salga caro.
 *   3. Comparar en tiempo constante, para no filtrar informacion por el tiempo.
 *
 * Formato guardado:  iteraciones:salBase64:hashBase64
 */
public final class HashContrasena {

    public static final int ITERACIONES = 210_000;
    public static final int BYTES_SAL = 16;
    public static final int BITS_CLAVE = 256;
    private static final String ALGORITMO = "PBKDF2WithHmacSHA256";

    private static final SecureRandom ALEATORIO = new SecureRandom();

    private HashContrasena() {
    }

    public static String hashear(String contrasena) {
        validar(contrasena);
        byte[] sal = new byte[BYTES_SAL];
        ALEATORIO.nextBytes(sal);
        byte[] hash = derivar(contrasena.toCharArray(), sal, ITERACIONES);

        return ITERACIONES + ":"
                + Base64.getEncoder().encodeToString(sal) + ":"
                + Base64.getEncoder().encodeToString(hash);
    }

    public static boolean coincide(String contrasena, String almacenado) {
        if (contrasena == null || almacenado == null) {
            return false;
        }
        String[] partes = almacenado.split(":");
        if (partes.length != 3) {
            throw new IllegalArgumentException("El hash almacenado no tiene el formato esperado");
        }
        int iteraciones;
        byte[] sal;
        byte[] esperado;
        try {
            iteraciones = Integer.parseInt(partes[0]);
            sal = Base64.getDecoder().decode(partes[1]);
            esperado = Base64.getDecoder().decode(partes[2]);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("El hash almacenado esta corrupto: " + e.getMessage());
        }

        byte[] calculado = derivar(contrasena.toCharArray(), sal, iteraciones);
        return MessageDigest.isEqual(esperado, calculado);
    }

    /** true si el hash se genero con menos iteraciones de las que hoy se exigen. */
    public static boolean necesitaRehash(String almacenado) {
        String[] partes = almacenado.split(":");
        if (partes.length != 3) {
            return true;
        }
        try {
            return Integer.parseInt(partes[0]) < ITERACIONES;
        } catch (NumberFormatException e) {
            return true;
        }
    }

    private static byte[] derivar(char[] contrasena, byte[] sal, int iteraciones) {
        try {
            PBEKeySpec especificacion = new PBEKeySpec(contrasena, sal, iteraciones, BITS_CLAVE);
            return SecretKeyFactory.getInstance(ALGORITMO).generateSecret(especificacion).getEncoded();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("No se pudo derivar el hash: " + e.getMessage(), e);
        }
    }

    private static void validar(String contrasena) {
        if (contrasena == null || contrasena.length() < 8) {
            throw new IllegalArgumentException("La contrasena debe tener al menos 8 caracteres");
        }
    }
}
