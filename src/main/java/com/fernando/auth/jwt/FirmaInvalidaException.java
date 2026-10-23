package com.fernando.auth.jwt;

public class FirmaInvalidaException extends JwtException {

    private static final long serialVersionUID = 1L;

    public FirmaInvalidaException(String mensaje) {
        super(mensaje);
    }
}
