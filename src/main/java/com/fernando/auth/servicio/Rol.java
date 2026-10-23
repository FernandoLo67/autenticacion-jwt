package com.fernando.auth.servicio;

public enum Rol {
    USUARIO,
    EDITOR,
    ADMIN;

    public static Rol desde(String nombre) {
        for (Rol rol : values()) {
            if (rol.name().equalsIgnoreCase(nombre)) {
                return rol;
            }
        }
        throw new IllegalArgumentException("Rol desconocido: " + nombre);
    }
}
