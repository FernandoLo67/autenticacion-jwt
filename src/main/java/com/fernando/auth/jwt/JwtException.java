package com.fernando.auth.jwt;

public class JwtException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public JwtException(String mensaje) {
        super(mensaje);
    }
}
