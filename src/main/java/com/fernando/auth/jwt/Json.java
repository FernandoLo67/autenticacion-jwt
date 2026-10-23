package com.fernando.auth.jwt;

import java.util.*;

/** Parser y serializador de JSON minimos, escritos a mano para no depender de librerias. */
final class Json {

    private final String texto;
    private int posicion;

    private Json(String texto) {
        this.texto = texto;
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> parsearObjeto(String json) {
        Json parser = new Json(json);
        parser.saltarEspacios();
        Object valor = parser.leerValor();
        if (!(valor instanceof Map)) {
            throw new TokenMalFormadoException("Se esperaba un objeto JSON");
        }
        return (Map<String, Object>) valor;
    }

    static String escribir(Object valor) {
        StringBuilder salida = new StringBuilder();
        escribirEn(salida, valor);
        return salida.toString();
    }

    private static void escribirEn(StringBuilder salida, Object valor) {
        if (valor == null) {
            salida.append("null");
        } else if (valor instanceof String) {
            String texto = (String) valor;
            salida.append('"');
            for (int i = 0; i < texto.length(); i++) {
                char c = texto.charAt(i);
                switch (c) {
                    case '"':
                        salida.append("\\\"");
                        break;
                    case '\\':
                        salida.append("\\\\");
                        break;
                    case '\n':
                        salida.append("\\n");
                        break;
                    case '\r':
                        salida.append("\\r");
                        break;
                    case '\t':
                        salida.append("\\t");
                        break;
                    default:
                        if (c < 0x20) {
                            salida.append(String.format("\\u%04x", (int) c));
                        } else {
                            salida.append(c);
                        }
                }
            }
            salida.append('"');
        } else if (valor instanceof Number || valor instanceof Boolean) {
            salida.append(valor);
        } else if (valor instanceof Map<?, ?>) {
            Map<?, ?> mapa = (Map<?, ?>) valor;
            salida.append('{');
            boolean primero = true;
            for (Map.Entry<?, ?> entrada : mapa.entrySet()) {
                if (!primero) {
                    salida.append(',');
                }
                primero = false;
                escribirEn(salida, String.valueOf(entrada.getKey()));
                salida.append(':');
                escribirEn(salida, entrada.getValue());
            }
            salida.append('}');
        } else if (valor instanceof Collection<?>) {
            Collection<?> lista = (Collection<?>) valor;
            salida.append('[');
            boolean primero = true;
            for (Object elemento : lista) {
                if (!primero) {
                    salida.append(',');
                }
                primero = false;
                escribirEn(salida, elemento);
            }
            salida.append(']');
        } else {
            escribirEn(salida, String.valueOf(valor));
        }
    }

    private Object leerValor() {
        saltarEspacios();
        if (posicion >= texto.length()) {
            throw new TokenMalFormadoException("JSON incompleto");
        }
        char c = texto.charAt(posicion);
        switch (c) {
            case '{':
                return leerObjeto();
            case '[':
                return leerArreglo();
            case '"':
                return leerTexto();
            case 't':
            case 'f':
                return leerBooleano();
            case 'n':
                return leerNulo();
            default:
                return leerNumero();
        }
    }

    private Map<String, Object> leerObjeto() {
        Map<String, Object> objeto = new LinkedHashMap<>();
        consumir('{');
        saltarEspacios();
        if (mirar() == '}') {
            consumir('}');
            return objeto;
        }
        while (true) {
            saltarEspacios();
            String clave = leerTexto();
            saltarEspacios();
            consumir(':');
            objeto.put(clave, leerValor());
            saltarEspacios();
            char siguiente = mirar();
            if (siguiente == ',') {
                consumir(',');
            } else if (siguiente == '}') {
                consumir('}');
                return objeto;
            } else {
                throw new TokenMalFormadoException("Se esperaba ',' o '}'");
            }
        }
    }

    private List<Object> leerArreglo() {
        List<Object> arreglo = new ArrayList<>();
        consumir('[');
        saltarEspacios();
        if (mirar() == ']') {
            consumir(']');
            return arreglo;
        }
        while (true) {
            arreglo.add(leerValor());
            saltarEspacios();
            char siguiente = mirar();
            if (siguiente == ',') {
                consumir(',');
            } else if (siguiente == ']') {
                consumir(']');
                return arreglo;
            } else {
                throw new TokenMalFormadoException("Se esperaba ',' o ']'");
            }
        }
    }

    private String leerTexto() {
        consumir('"');
        StringBuilder resultado = new StringBuilder();
        while (true) {
            if (posicion >= texto.length()) {
                throw new TokenMalFormadoException("Cadena sin cerrar");
            }
            char c = texto.charAt(posicion++);
            if (c == '"') {
                return resultado.toString();
            }
            if (c == '\\') {
                char escape = texto.charAt(posicion++);
                switch (escape) {
                    case '"':
                        resultado.append('"');
                        break;
                    case '\\':
                        resultado.append('\\');
                        break;
                    case '/':
                        resultado.append('/');
                        break;
                    case 'n':
                        resultado.append('\n');
                        break;
                    case 'r':
                        resultado.append('\r');
                        break;
                    case 't':
                        resultado.append('\t');
                        break;
                    case 'b':
                        resultado.append('\b');
                        break;
                    case 'f':
                        resultado.append('\f');
                        break;
                    case 'u':
                        resultado.append((char) Integer.parseInt(texto.substring(posicion, posicion + 4), 16));
                        posicion += 4;
                        break;
                    default:
                        throw new TokenMalFormadoException("Escape desconocido: \\" + escape);
                }
            } else {
                resultado.append(c);
            }
        }
    }

    private Object leerNumero() {
        int inicio = posicion;
        if (mirar() == '-') {
            posicion++;
        }
        while (posicion < texto.length()
                && (Character.isDigit(texto.charAt(posicion)) || "+-.eE".indexOf(texto.charAt(posicion)) >= 0)) {
            posicion++;
        }
        String crudo = texto.substring(inicio, posicion);
        try {
            if (crudo.contains(".") || crudo.contains("e") || crudo.contains("E")) {
                return Double.parseDouble(crudo);
            }
            return Long.parseLong(crudo);
        } catch (NumberFormatException e) {
            throw new TokenMalFormadoException("Numero invalido: " + crudo);
        }
    }

    private Boolean leerBooleano() {
        if (texto.startsWith("true", posicion)) {
            posicion += 4;
            return Boolean.TRUE;
        }
        if (texto.startsWith("false", posicion)) {
            posicion += 5;
            return Boolean.FALSE;
        }
        throw new TokenMalFormadoException("Booleano invalido");
    }

    private Object leerNulo() {
        if (texto.startsWith("null", posicion)) {
            posicion += 4;
            return null;
        }
        throw new TokenMalFormadoException("Valor invalido");
    }

    private char mirar() {
        if (posicion >= texto.length()) {
            throw new TokenMalFormadoException("JSON incompleto");
        }
        return texto.charAt(posicion);
    }

    private void consumir(char esperado) {
        if (posicion >= texto.length() || texto.charAt(posicion) != esperado) {
            throw new TokenMalFormadoException("Se esperaba '" + esperado + "'");
        }
        posicion++;
    }

    private void saltarEspacios() {
        while (posicion < texto.length() && Character.isWhitespace(texto.charAt(posicion))) {
            posicion++;
        }
    }
}
