package com.fernando.auth.jwt;

import java.time.Instant;

public class TokenExpiradoException extends JwtException {

    private static final long serialVersionUID = 1L;

    public TokenExpiradoException(Instant expiracion) {
        super("El token expiro el " + expiracion);
    }
}
