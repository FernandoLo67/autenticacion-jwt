package com.fernando.auth.servicio;

import java.util.LinkedHashSet;
import java.util.Set;

public class Usuario {

    private final String usuario;
    private final String email;
    private final Set<Rol> roles;
    private String hashContrasena;
    private boolean activo = true;

    public Usuario(String usuario, String email, String hashContrasena, Set<Rol> roles) {
        if (usuario == null || usuario.isBlank()) {
            throw new IllegalArgumentException("El nombre de usuario es obligatorio");
        }
        if (email == null || !email.matches("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$")) {
            throw new IllegalArgumentException("Email invalido: " + email);
        }
        this.usuario = usuario.trim().toLowerCase();
        this.email = email.trim();
        this.hashContrasena = hashContrasena;
        this.roles = new LinkedHashSet<>(roles.isEmpty() ? Set.of(Rol.USUARIO) : roles);
    }

    public String getUsuario() { return usuario; }
    public String getEmail() { return email; }
    public String getHashContrasena() { return hashContrasena; }
    public boolean estaActivo() { return activo; }

    public Set<Rol> getRoles() {
        return Set.copyOf(roles);
    }

    public Set<String> nombresDeRoles() {
        return roles.stream().map(Enum::name)
                .collect(java.util.stream.Collectors.toCollection(LinkedHashSet::new));
    }

    public void cambiarHash(String nuevoHash) {
        this.hashContrasena = nuevoHash;
    }

    public void desactivar() {
        this.activo = false;
    }

    public void activar() {
        this.activo = true;
    }

    @Override
    public String toString() {
        return usuario + " <" + email + "> " + roles + (activo ? "" : " [INACTIVO]");
    }
}
