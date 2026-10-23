package com.fernando.auth.servicio;

public class AutenticacionException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public AutenticacionException(String mensaje) {
        super(mensaje);
    }
}
