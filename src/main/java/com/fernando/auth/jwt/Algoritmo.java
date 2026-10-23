package com.fernando.auth.jwt;

public enum Algoritmo {

    HS256("HmacSHA256"),
    HS384("HmacSHA384"),
    HS512("HmacSHA512");

    private final String nombreJca;

    Algoritmo(String nombreJca) {
        this.nombreJca = nombreJca;
    }

    public String getNombreJca() {
        return nombreJca;
    }

    public static Algoritmo desde(String nombre) {
        if (nombre == null) {
            throw new TokenMalFormadoException("El encabezado no declara algoritmo");
        }
        // "none" es un algoritmo real del estandar y es exactamente el vector
        // del ataque clasico contra JWT: se rechaza siempre.
        if (nombre.equalsIgnoreCase("none")) {
            throw new FirmaInvalidaException("El algoritmo 'none' no esta permitido");
        }
        for (Algoritmo algoritmo : values()) {
            if (algoritmo.name().equalsIgnoreCase(nombre)) {
                return algoritmo;
            }
        }
        throw new FirmaInvalidaException("Algoritmo no soportado: " + nombre);
    }
}
