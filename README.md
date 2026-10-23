# Autenticacion con JWT

Sistema de autenticacion completo con **JSON Web Tokens implementados desde cero** sobre `javax.crypto`: sin `jjwt`, sin `java-jwt`, sin Spring Security. Incluye hash de contrasenas con PBKDF2, roles, tokens de refresco con rotacion y bloqueo por intentos fallidos.

## Que es un JWT, en tres lineas

```
base64url(encabezado) . base64url(contenido) . base64url(firma)
```

El encabezado dice con que algoritmo se firmo, el contenido lleva los datos (quien sos, que roles tenes, cuando expira) y la firma es el HMAC de los dos primeros segmentos. **Cualquiera puede leer el contenido** —no esta cifrado, solo codificado— pero nadie puede modificarlo sin la clave.

## Las cuatro trampas de seguridad que este codigo evita

**1. El ataque `alg: none`.** El estandar JWT admite el algoritmo `"none"`, que significa "sin firma". Un atacante cambia el encabezado a `alg:none`, se pone `"roles":["ADMIN"]` y borra la firma. Muchas librerias lo aceptaron durante anos. Aqui `Algoritmo.desde()` lo rechaza explicitamente.

**2. Sustitucion de algoritmo.** Si el verificador confia en el `alg` que trae el token, el token decide como se valida a si mismo. Aqui **el algoritmo lo fija el servidor** al construir el emisor; un token que declare otro se rechaza aunque la firma cuadre.

**3. Comparacion de firmas en tiempo variable.** Un `equals()` normal corta en el primer byte distinto, y esa diferencia de microsegundos permite reconstruir la firma byte a byte. Se usa `MessageDigest.isEqual()`, que compara en tiempo constante.

**4. Enumeracion de usuarios.** Si el login responde "usuario no existe" y "contrasena incorrecta" por separado, regala la lista de usuarios validos. Aqui los dos casos devuelven **exactamente el mismo mensaje**, y hay una prueba que compara ambos textos para que siga siendo asi.

## Contrasenas: PBKDF2-HMAC-SHA256

```
formato guardado:  iteraciones : sal(base64) : hash(base64)
```

- **Sal aleatoria de 16 bytes por contrasena**, para que dos usuarios con la misma clave no compartan hash y las tablas precalculadas no sirvan de nada.
- **210.000 iteraciones**, el minimo que recomienda OWASP para PBKDF2-SHA256, para que probar contrasenas salga caro.
- **Comparacion en tiempo constante**, igual que las firmas.
- `necesitaRehash()` detecta hashes viejos hechos con menos iteraciones, para poder subir el costo con el tiempo sin invalidar contrasenas.

## Tokens de acceso y de refresco

| | Acceso | Refresco |
|---|---|---|
| Vida | 15 minutos | 7 dias |
| Viaja | en cada peticion | solo al renovar |
| Si lo roban | caduca solo, pronto | se revoca |

El refresco usa **rotacion**: al canjearlo se emite un par nuevo y el anterior queda en la lista negra. Reutilizar un refresco viejo es senal de robo y se rechaza.

## Que muestra este proyecto

- Criptografia aplicada con la API estandar de Java: `Mac` (HMAC-SHA256/384/512), `SecretKeyFactory` (PBKDF2), `SecureRandom`, `MessageDigest.isEqual`.
- Base64Url sin relleno (RFC 7515), con pruebas de que no aparecen `=`, `+` ni `/`.
- Parser de JSON propio para el contenido del token.
- Reloj inyectable: expiracion, `nbf` y tolerancia de desfase se prueban al instante, sin `Thread.sleep`.
- Tolerancia de reloj de 30 segundos entre servidores, con pruebas de los dos lados del limite.
- Autorizacion por roles y bloqueo tras 5 intentos fallidos.

## Pruebas

**59 pruebas.** Las que mas valen son las adversariales: token con el contenido manipulado, token firmado con otra clave, `alg:none`, algoritmo sustituido, token de refresco usado como token de acceso, refresco reutilizado despues de la rotacion, y token emitido por un emisor ajeno.

## Como ejecutar

```bash
mvn package
java -jar target/autenticacion-jwt-1.0.0.jar   # demo que recorre todo el flujo
mvn test
```
