package com.fernando.auth.jwt;

public class TokenMalFormadoException extends JwtException {

    private static final long serialVersionUID = 1L;

    public TokenMalFormadoException(String mensaje) {
        super(mensaje);
    }
}
