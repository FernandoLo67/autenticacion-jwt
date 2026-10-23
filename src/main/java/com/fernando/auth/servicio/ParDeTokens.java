package com.fernando.auth.servicio;

import java.util.Objects;

public final class ParDeTokens {

    private final String tokenDeAcceso;
    private final String tokenDeRefresco;

    public ParDeTokens(String tokenDeAcceso, String tokenDeRefresco) {
        this.tokenDeAcceso = tokenDeAcceso;
        this.tokenDeRefresco = tokenDeRefresco;
    }

    public String tokenDeAcceso() {
        return tokenDeAcceso;
    }

    public String tokenDeRefresco() {
        return tokenDeRefresco;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof ParDeTokens)) {
            return false;
        }
        ParDeTokens that = (ParDeTokens) o;
        return Objects.equals(tokenDeAcceso, that.tokenDeAcceso)
                && Objects.equals(tokenDeRefresco, that.tokenDeRefresco);
    }

    @Override
    public int hashCode() {
        return Objects.hash(tokenDeAcceso, tokenDeRefresco);
    }

    @Override
    public String toString() {
        return "ParDeTokens[tokenDeAcceso=" + tokenDeAcceso + ", tokenDeRefresco=" + tokenDeRefresco + "]";
    }
}
