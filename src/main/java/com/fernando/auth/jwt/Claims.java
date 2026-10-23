package com.fernando.auth.jwt;

import java.time.Instant;
import java.util.*;

/**
 * Contenido del token. Los nombres cortos (sub, exp, iat...) son los que
 * define el estandar JWT (RFC 7519); aqui se exponen con nombres legibles.
 */
public final class Claims {

    public static final String SUJETO = "sub";
    public static final String EMISOR = "iss";
    public static final String AUDIENCIA = "aud";
    public static final String EXPIRACION = "exp";
    public static final String EMITIDO_EN = "iat";
    public static final String NO_ANTES_DE = "nbf";
    public static final String ID_TOKEN = "jti";
    public static final String ROLES = "roles";

    private final Map<String, Object> valores;

    Claims(Map<String, Object> valores) {
        this.valores = new LinkedHashMap<>(valores);
    }

    public static Constructor constructor() {
        return new Constructor();
    }

    public Object get(String clave) {
        return valores.get(clave);
    }

    public String texto(String clave) {
        Object valor = valores.get(clave);
        return valor == null ? null : String.valueOf(valor);
    }

    public Instant instante(String clave) {
        Object valor = valores.get(clave);
        if (valor == null) {
            return null;
        }
        if (valor instanceof Number) {
            return Instant.ofEpochSecond(((Number) valor).longValue());
        }
        throw new TokenMalFormadoException("El claim '" + clave + "' deberia ser un numero de segundos");
    }

    public String sujeto() { return texto(SUJETO); }
    public String emisor() { return texto(EMISOR); }
    public String audiencia() { return texto(AUDIENCIA); }
    public String idToken() { return texto(ID_TOKEN); }
    public Instant expiracion() { return instante(EXPIRACION); }
    public Instant emitidoEn() { return instante(EMITIDO_EN); }
    public Instant noAntesDe() { return instante(NO_ANTES_DE); }

    @SuppressWarnings("unchecked")
    public Set<String> roles() {
        Object valor = valores.get(ROLES);
        if (valor == null) {
            return Set.of();
        }
        if (valor instanceof Collection<?>) {
            return ((Collection<Object>) valor).stream()
                    .map(String::valueOf)
                    .collect(java.util.stream.Collectors.toCollection(LinkedHashSet::new));
        }
        return Set.of(String.valueOf(valor));
    }

    public boolean tieneRol(String rol) {
        return roles().contains(rol);
    }

    public Map<String, Object> comoMapa() {
        return Map.copyOf(valores);
    }

    @Override
    public String toString() {
        return valores.toString();
    }

    /** Constructor fluido de claims. */
    public static final class Constructor {

        private final Map<String, Object> valores = new LinkedHashMap<>();

        public Constructor sujeto(String sujeto) {
            valores.put(SUJETO, sujeto);
            return this;
        }

        public Constructor emisor(String emisor) {
            valores.put(EMISOR, emisor);
            return this;
        }

        public Constructor audiencia(String audiencia) {
            valores.put(AUDIENCIA, audiencia);
            return this;
        }

        public Constructor idToken(String id) {
            valores.put(ID_TOKEN, id);
            return this;
        }

        public Constructor roles(Collection<String> roles) {
            valores.put(ROLES, new ArrayList<>(roles));
            return this;
        }

        public Constructor expiracion(Instant instante) {
            valores.put(EXPIRACION, instante.getEpochSecond());
            return this;
        }

        public Constructor emitidoEn(Instant instante) {
            valores.put(EMITIDO_EN, instante.getEpochSecond());
            return this;
        }

        public Constructor noAntesDe(Instant instante) {
            valores.put(NO_ANTES_DE, instante.getEpochSecond());
            return this;
        }

        public Constructor con(String clave, Object valor) {
            valores.put(clave, valor);
            return this;
        }

        public Claims construir() {
            return new Claims(valores);
        }
    }
}
