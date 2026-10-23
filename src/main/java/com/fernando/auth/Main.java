package com.fernando.auth;

import com.fernando.auth.jwt.*;
import com.fernando.auth.servicio.*;

import java.time.Instant;
import java.util.Set;

public class Main {

    private static final String CLAVE = "una-clave-secreta-de-al-menos-32-bytes-para-hmac";

    public static void main(String[] args) {
        EmisorJwt emisor = new EmisorJwt(CLAVE, Algoritmo.HS256, Instant::now);
        ServicioAutenticacion auth = new ServicioAutenticacion(emisor, Instant::now);

        System.out.println("=== Autenticacion con JWT ===\n");

        System.out.println("1. Registrando usuarios...");
        auth.registrar("daniel", "daniel@ejemplo.com", "contrasena-segura", Set.of(Rol.ADMIN));
        auth.registrar("ana", "ana@ejemplo.com", "otra-contrasena", Set.of(Rol.USUARIO));
        auth.listarUsuarios().forEach(u -> System.out.println("   " + u));

        System.out.println("\n2. Iniciando sesion como daniel...");
        ParDeTokens tokens = auth.iniciarSesion("daniel", "contrasena-segura");
        System.out.println("   token de acceso:   " + acortar(tokens.tokenDeAcceso()));
        System.out.println("   token de refresco: " + acortar(tokens.tokenDeRefresco()));

        System.out.println("\n3. Contenido del token (los 3 segmentos):");
        String[] partes = tokens.tokenDeAcceso().split("\\.");
        System.out.println("   encabezado: " + Base64Url.decodificarTexto(partes[0]));
        System.out.println("   contenido:  " + Base64Url.decodificarTexto(partes[1]));
        System.out.println("   firma:      " + acortar(partes[2]) + "  (no es legible: es el HMAC)");

        System.out.println("\n4. Autorizacion por rol:");
        System.out.println("   daniel como ADMIN  -> "
                + auth.autorizar(tokens.tokenDeAcceso(), Rol.ADMIN).sujeto() + " autorizado");

        ParDeTokens deAna = auth.iniciarSesion("ana", "otra-contrasena");
        try {
            auth.autorizar(deAna.tokenDeAcceso(), Rol.ADMIN);
        } catch (AutenticacionException e) {
            System.out.println("   ana como ADMIN     -> rechazada: " + e.getMessage());
        }

        System.out.println("\n5. Token manipulado:");
        String manipulado = manipular(tokens.tokenDeAcceso());
        try {
            emisor.verificar(manipulado);
            System.out.println("   ERROR: no deberia haberse aceptado");
        } catch (JwtException e) {
            System.out.println("   rechazado: " + e.getMessage());
        }

        System.out.println("\n6. Refresco de sesion:");
        ParDeTokens renovados = auth.refrescar(tokens.tokenDeRefresco());
        System.out.println("   nuevo token de acceso: " + acortar(renovados.tokenDeAcceso()));
        try {
            auth.refrescar(tokens.tokenDeRefresco());
        } catch (AutenticacionException e) {
            System.out.println("   reutilizar el refresco viejo -> rechazado: " + e.getMessage());
        }

        System.out.println("\n7. Cierre de sesion:");
        auth.cerrarSesion(renovados.tokenDeRefresco());
        try {
            auth.refrescar(renovados.tokenDeRefresco());
        } catch (AutenticacionException e) {
            System.out.println("   refrescar tras cerrar sesion -> rechazado: " + e.getMessage());
        }
    }

    /** Cambia un caracter del contenido para simular una manipulacion. */
    private static String manipular(String token) {
        String[] partes = token.split("\\.");
        char[] contenido = partes[1].toCharArray();
        contenido[5] = contenido[5] == 'a' ? 'b' : 'a';
        return partes[0] + "." + new String(contenido) + "." + partes[2];
    }

    private static String acortar(String texto) {
        return texto.length() <= 42 ? texto : texto.substring(0, 39) + "...";
    }
}
