# Hash Forge

[![PyPI version](https://badge.fury.io/py/hash-forge.svg)](https://pypi.org/project/hash-forge/) ![Build Status](https://github.com/Zozi96/hash-forge/actions/workflows/unittest.yml/badge.svg)  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![Python Versions](https://img.shields.io/pypi/pyversions/hash-forge.svg)](https://pypi.org/project/hash-forge/) [![Downloads](https://pepy.tech/badge/hash-forge)](https://pepy.tech/project/hash-forge) [![GitHub issues](https://img.shields.io/github/issues/Zozi96/hash-forge)](https://github.com/Zozi96/hash-forge/issues) ![Project Status](https://img.shields.io/badge/status-active-brightgreen.svg) [![Code Style: Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black) [![Contributions welcome](https://img.shields.io/badge/contributions-welcome-blue.svg)](https://github.com/Zozi96/hash-forge/issues)

**Hash Forge** es una biblioteca ligera en Python diseñada para simplificar el proceso de hash y verificación de datos utilizando una variedad de algoritmos de hash seguros.

## Descripción General

Hash Forge es una herramienta flexible y segura de gestión de hash que admite múltiples algoritmos de hash. Esta herramienta le permite realizar hash y verificar datos utilizando algoritmos populares, facilitando su integración en proyectos donde el hash de contraseñas o la integridad de datos es fundamental.

## Características

- **Múltiples Algoritmos de Hash**: Admite bcrypt, Scrypt, Argon2, Blake2, Blake3, PBKDF2, SHA-3, Whirlpool y RIPEMD-160.
- **Soporte para Async/Await**: Operaciones no bloqueantes con `hash_async()`, `verify_async()`, y procesamiento por lotes.
- **Patrón Builder**: API fluida y encadenable para una configuración elegante.
- **Gestión de Configuración**: Carga ajustes desde variables de entorno, archivos JSON o código.
- **Hashing y Verificación**: Fácil hash de cadenas y verificación de integridad.
- **Rotación de Hash**: Migrar de forma fluida los hashes a un nuevo algoritmo con `rotate()`.
- **Políticas de Contraseña**: Use perfiles `PasswordHashPolicy` para valores predeterminados seguros y `verify_and_update()`.
- **Inspección de Hash**: Recupera metadatos del algoritmo de cualquier hash con `inspect()`.
- **Detección de Rehash**: Detecta automáticamente si un hash necesita ser rehasheado basado en parámetros o algoritmos desactualizados.
- **API Tipada**: Completas anotaciones de tipos con `AlgorithmType` para mejor soporte de IDE.
- **Optimizado para Rendimiento**: Búsqueda O(1) del hasher, operaciones por lotes async 3-5x más rápidas.
- **Enfocado en Seguridad**: Aplica parámetros de seguridad mínimos y usa generación aleatoria criptográficamente segura.
- **Bien Documentado**: Ejemplos comprehensivos, directrices de seguridad y documentación de contribución.

## Instalación

```bash
pip install hash-forge
```

### Dependencias Opcionales

Hash Forge proporciona dependencias opcionales para algoritmos específicos de hash. Para instalar estas, use:

- **Soporte para bcrypt**:

  ```bash
  pip install "hash-forge[bcrypt]"
  ```
- **Soporte para Argon2**:

  ```bash
  pip install "hash-forge[argon2]"
  ```
- **Soporte para Whirlpool y RIPEMD-160**:

  ```bash
  pip install "hash-forge[crypto]"
  ```
- **Soporte para Blake3**:

  ```bash
  pip install "hash-forge[blake3]"
  ```

## Primeros Pasos

```python
from hash_forge import HashManager

# La instalación base funciona con PBKDF2-SHA256
hash_manager = HashManager.from_algorithms("pbkdf2_sha256")

# Hash de una contraseña
hashed = hash_manager.hash("my_secure_password")

# Verificar una contraseña
is_valid = hash_manager.verify("my_secure_password", hashed)
print(is_valid)  # True

# Comprobar si necesita actualización
needs_update = hash_manager.needs_rehash(hashed)
```

## Uso

### Ejemplo Básico

```python
from hash_forge import HashManager, AlgorithmType
from hash_forge.hashers import PBKDF2Sha256Hasher

# Inicializar HashManager con PBKDF2Hasher
hash_manager = HashManager(PBKDF2Sha256Hasher())

# Hash de una cadena
hashed_value = hash_manager.hash("my_secure_password")

# Verificar la cadena contra el valor hasheado
is_valid = hash_manager.verify("my_secure_password", hashed_value)
print(is_valid)  # Salida: True

# Comprobar si el hash necesita ser rehasheado
needs_rehash = hash_manager.needs_rehash(hashed_value)
print(needs_rehash)  # Salida: False
```

### Ejemplos

Consulte el directorio [`examples/`](examples/) para más ejemplos prácticos:

- **[basic_usage.py](examples/basic_usage.py)** - Operaciones fundamentales y patrones comunes
- **[async_fastapi.py](examples/async_fastapi.py)** - Integración con FastAPI y soporte async
- **[builder_pattern.py](examples/builder_pattern.py)** - Ejemplos de la API del patrón builder

### Quick Hash (Nuevo en v2.1.0)

Para hashing simple sin crear una instancia de HashManager:

```python
from hash_forge import HashManager, AlgorithmType

# Quick hash con algoritmo predeterminado (PBKDF2-SHA256)
hashed = HashManager.quick_hash("my_password")

# Quick hash con algoritmo específico (¡Autocomplete de IDE!)
algorithm: AlgorithmType = "argon2"
hashed = HashManager.quick_hash("my_password", algorithm=algorithm)

# Quick hash con parámetros específicos del algoritmo
hashed = HashManager.quick_hash("my_password", algorithm="pbkdf2_sha256", iterations=200_000)
hashed = HashManager.quick_hash("my_password", algorithm="bcrypt", rounds=14)
hashed = HashManager.quick_hash("my_password", algorithm="argon2", time_cost=4)
```

### Patrón Factory (Nuevo en v2.1.0)

Crear instancias de HashManager usando nombres de algoritmos:

```python
from hash_forge import HashManager, AlgorithmType

# Crear HashManager desde nombres de algoritmos
hash_manager = HashManager.from_algorithms("pbkdf2_sha256", "argon2", "bcrypt")

# Con tipado seguro
algorithms: list[AlgorithmType] = ["pbkdf2_sha256", "bcrypt_sha256"]
hash_manager = HashManager.from_algorithms(*algorithms)

# Nota: from_algorithms() crea hashers con parámetros predeterminados
# Para parámetros personalizados, cree hashers individualmente
hash_manager = HashManager.from_algorithms("pbkdf2_sha256", "bcrypt", "argon2")
```

> **Nota:** El primer hasher proporcionado durante la inicialización de `HashManager` será el **hasher preferido** usado para operaciones de hash, aunque cualquier hasher disponible puede usarse para verificación.

### Algoritmos Disponibles

Actualmente admite los siguientes algoritmos con sus identificadores `AlgorithmType`:

| Algoritmo | Identificador | Nivel de Seguridad | Notas |
|-----------|------------|----------------|-------|
| **PBKDF2-SHA256** | `"pbkdf2_sha256"` | Alto | Predeterminado, 150K iteraciones mínimas |
| **PBKDF2-SHA1** | `"pbkdf2_sha1"` | Medio | Soporte legado |
| **bcrypt** | `"bcrypt"` | Alto | 12 rondas mínimas |
| **bcrypt-SHA256** | `"bcrypt_sha256"` | Alto | Con pre-hash SHA256 |
| **Argon2** | `"argon2"` | Muy Alto | Función resistente a memoria |
| **Scrypt** | `"scrypt"` | Alto | Función resistente a memoria |
| **Blake2** | `"blake2"` | Solo digest | Hash criptográfico rápido, no para hash de contraseñas |
| **Blake3** | `"blake3"` | Solo digest | Hash criptográfico rápido, no para hash de contraseñas |
| **SHA-3 256** | `"sha3_256"` | Solo digest | solo stdlib, sin dependencias extra |
| **SHA-3 512** | `"sha3_512"` | Solo digest | solo stdlib, sin dependencias extra |
| **Whirlpool** | `"whirlpool"` | Obsoleto | Solo compatibilidad legada; hashing nuevo deshabilitado por defecto |
| **RIPEMD-160** | `"ripemd160"` | Legado | Digest de 160 bits |

### API de Políticas de Contraseña

```python
from hash_forge import HashManager, PasswordHashPolicy

# Requiere: pip install "hash-forge[argon2]"
hash_manager = HashManager.from_policy(PasswordHashPolicy.recommended())
hashed = hash_manager.hash("my_secure_password")

ok, replacement_hash = hash_manager.verify_and_update("my_secure_password", hashed)
if replacement_hash is not None:
    # Guardar replacement_hash; parámetros o algoritmo preferido cambió.
    ...
```

Use `PasswordHashPolicy.fips()` cuando necesite un perfil PBKDF2-HMAC-SHA256, o
`PasswordHashPolicy.legacy_compat()` cuando migre hashes almacenados más antiguos.

### Parámetros Específicos del Algoritmo

Diferentes algoritmos admiten diferentes parámetros. Use `quick_hash()` para personalización específica del algoritmo:

```python
from hash_forge import HashManager

# Algoritmos PBKDF2
HashManager.quick_hash("password", algorithm="pbkdf2_sha256", iterations=200_000, salt_length=16)
HashManager.quick_hash("password", algorithm="pbkdf2_sha1", iterations=150_000)

# Algoritmos BCrypt  
HashManager.quick_hash("password", algorithm="bcrypt", rounds=14)
HashManager.quick_hash("password", algorithm="bcrypt_sha256", rounds=12)

# Argon2
HashManager.quick_hash("password", algorithm="argon2", time_cost=4, memory_cost=65536, parallelism=1)

# Scrypt
HashManager.quick_hash("password", algorithm="scrypt", work_factor=32768, block_size=8, parallelism=1)

# Blake2 (con clave opcional)
HashManager.quick_hash("password", algorithm="blake2", key="secret_key")

# Blake3 (con clave opcional)  
HashManager.quick_hash("password", algorithm="blake3", key="secret_key")

# SHA-3 (solo stdlib — sin dependencias extra)
HashManager.quick_hash("password", algorithm="sha3_256")
HashManager.quick_hash("password", algorithm="sha3_512")

# Digest legado (nuevo hashing Whirlpool deshabilitado por defecto)
HashManager.quick_hash("password", algorithm="ripemd160")
```

### Inicialización Tradicional

Para control total sobre parámetros, inicialice `HashManager` con instancias individuales de hasher:

```python
from hash_forge import HashManager
from hash_forge.hashers import (
    Argon2Hasher,
    BCryptSha256Hasher,
    Blake2Hasher,
    PBKDF2Sha256Hasher,
    Ripemd160Hasher,
    ScryptHasher,
    SHA3_256Hasher,
    SHA3_512Hasher,
    Blake3Hasher
)

hash_manager = HashManager(
    PBKDF2Sha256Hasher(iterations=200_000),  # Más iteraciones
    BCryptSha256Hasher(rounds=14),           # Más rondas
    Argon2Hasher(time_cost=4),               # Parámetros personalizados
    ScryptHasher(),
    SHA3_256Hasher(),
    SHA3_512Hasher(),
    Ripemd160Hasher(),
    Blake2Hasher('MySecretKey'),
    Blake3Hasher()
)
```

### Verificación de un Hash

Use el método `verify` para comparar una cadena con su contraparte hasheada:

```python
is_valid = hash_manager.verify("my_secure_password", hashed_value)
```

### Comprobación de Rehash

Puede comprobar si un hash necesita ser rehasheado (por ejemplo, si los parámetros del algoritmo de hash están desactualizados):

```python
needs_rehash = hash_manager.needs_rehash(hashed_value)
```

### Rotación de Hash

`rotate()` verifica una contraseña contra un hash existente, luego vuelve a hashearla con el hasher preferido. Devuelve `None` si la verificación falla — sin excepción, sin exponer la texto sin formato al llamador.

Esta es la forma segura de migrar contraseñas de un algoritmo legado a uno nuevo en el próximo inicio de sesión:

```python
from hash_forge import HashManager

# Manager configurado con el nuevo algoritmo preferido
hash_manager = HashManager.from_algorithms("argon2", "pbkdf2_sha256")

# En el inicio de sesión, intentar rotación
old_hash = get_stored_hash(user_id)  # por ejemplo, un hash pbkdf2_sha256
new_hash = hash_manager.rotate(user_password, old_hash)

if new_hash is not None:
    save_hash(user_id, new_hash)  # ahora almacenado como argon2
    print("Contraseña migrada a argon2")
else:
    print("Contraseña incorrecta")
```

### Inspección de Hash

`inspect()` devuelve un diccionario con metadatos sobre un hash almacenado — nombre del algoritmo y cualquier parámetro específico del algoritmo, sin exponer el valor raw del hash ni la sal.

```python
from hash_forge import HashManager
from hash_forge.hashers import PBKDF2Sha256Hasher, SHA3_256Hasher

hash_manager = HashManager(PBKDF2Sha256Hasher(), SHA3_256Hasher())

pbkdf2_hash = HashManager.quick_hash("password", algorithm="pbkdf2_sha256", iterations=200_000)
print(hash_manager.inspect(pbkdf2_hash))
# {'algorithm': 'pbkdf2_sha256', 'category': 'password', 'deprecated': False, 'iterations': 200000}

sha3_hash = HashManager.quick_hash("password", algorithm="sha3_256")
print(hash_manager.inspect(sha3_hash))
# {'algorithm': 'sha3_256', 'category': 'digest', 'deprecated': False}

print(hash_manager.inspect("unknown$abc$def"))
# None
```

### Listar Algoritmos Registrados

`list_algorithms()` devuelve los nombres de los algoritmos registrados en la instancia actual del manager:

```python
from hash_forge import HashManager

hash_manager = HashManager.from_algorithms("argon2", "pbkdf2_sha256", "sha3_256")
print(hash_manager.list_algorithms())
# ['argon2', 'pbkdf2_sha256', 'sha3_256']
```

### Repr

`HashManager` tiene un `__repr__` legible que muestra el algoritmo preferido y todos los algoritmos registrados:

```python
from hash_forge import HashManager

hash_manager = HashManager.from_algorithms("argon2", "pbkdf2_sha256")
print(repr(hash_manager))
# HashManager(preferred='argon2', algorithms=['argon2', 'pbkdf2_sha256'])
```

### Soporte Async (Nuevo en v3.0.0)

Hash Forge proporciona soporte completo async/await para operaciones no bloqueantes. Todos los métodos sincrónicos tienen equivalentes async que se ejecutan en un thread pool executor para evitar bloquear el event loop.

Ejemplos usando Argon2 requieren `pip install "hash-forge[argon2]"`.

#### Operaciones Async Básicas

```python
import asyncio
from hash_forge import HashManager

async def main():
    hash_manager = HashManager.from_algorithms("argon2")

    # Hashing async - ejecuta hash sincrónico en thread pool
    hashed = await hash_manager.hash_async("my_password")
    print(f"Hashed: {hashed}")

    # Verificación async - verificación no bloqueante
    is_valid = await hash_manager.verify_async("my_password", hashed)
    print(f"Valid: {is_valid}")  # True

    # Comprobación async de rehash
    needs_rehash = await hash_manager.needs_rehash_async(hashed)
    print(f"Needs rehash: {needs_rehash}")  # False

asyncio.run(main())
```

#### Operaciones por Lotes

Procesar múltiples contraseñas concurrentemente para mejor rendimiento:

```python
import asyncio
from hash_forge import HashManager

async def batch_example():
    hash_manager = HashManager.from_algorithms("pbkdf2_sha256")

    # Hash de múltiples contraseñas concurrentemente
    passwords = ["user1_pass", "user2_pass", "user3_pass", "user4_pass"]
    hashes = await hash_manager.hash_many_async(passwords)

    # hashes es una lista con el mismo orden que passwords
    for password, hash_value in zip(passwords, hashes):
        print(f"{password} -> {hash_value[:50]}...")

    # Verificar múltiples pares contraseña-hash concurrentemente
    pairs = [
        ("user1_pass", hashes[0]),
        ("user2_pass", hashes[1]),
        ("wrong_password", hashes[2]),  # Esto será False
    ]
    results = await hash_manager.verify_many_async(pairs)
    print(f"Results: {results}")  # [True, True, False]

asyncio.run(batch_example())
```

#### Integración con Frameworks Web

Ideal para frameworks web async como FastAPI, Sanic o aiohttp:

```python
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from hash_forge import HashManager

app = FastAPI()
hash_manager = HashManager.from_algorithms("argon2")

class LoginRequest(BaseModel):
    username: str
    password: str

@app.post("/register")
async def register(request: LoginRequest):
    # Hash de contraseña no bloqueante
    hashed = await hash_manager.hash_async(request.password)
    # Guardar usuario con hash de contraseña en base de datos
    return {"username": request.username, "password_hash": hashed}

@app.post("/login")
async def login(request: LoginRequest):
    # Obtener usuario de base de datos (simulado)
    stored_hash = get_user_hash(request.username)

    # Verificación de contraseña no bloqueante
    is_valid = await hash_manager.verify_async(request.password, stored_hash)

    if not is_valid:
        raise HTTPException(status_code=401, detail="Credenciales inválidas")

    return {"message": "Login exitoso"}
```

#### Beneficios de Rendimiento

Los métodos async son especialmente útiles cuando:
- Procesar múltiples contraseñas en paralelo
- Integración con frameworks web async
- Evitar bloquear el event loop durante operaciones de hash costosas
- Construir aplicaciones async reactivas

```python
import asyncio
import time
from hash_forge import HashManager

async def performance_comparison():
    hash_manager = HashManager.from_algorithms("argon2")
    passwords = [f"password_{i}" for i in range(10)]

    # Secuencial (bloqueante)
    start = time.time()
    hashes_sync = [hash_manager.hash(pwd) for pwd in passwords]
    sync_time = time.time() - start

    # Concurrente (no bloqueante)
    start = time.time()
    hashes_async = await hash_manager.hash_many_async(passwords)
    async_time = time.time() - start

    print(f"Secuencial: {sync_time:.2f}s")
    print(f"Concurrente: {async_time:.2f}s")
    print(f"Speedup: {sync_time/async_time:.2f}x")

asyncio.run(performance_comparison())
```

### Gestión de Configuración (Nuevo en v3.0.0)

Cargar configuración desde variables de entorno, archivos JSON o programáticamente:

```python
from hash_forge import HashManager
from hash_forge.config import HashForgeConfig

# Desde variables de entorno
# export HASH_FORGE_PBKDF2_ITERATIONS=200000
# export HASH_FORGE_BCRYPT_ROUNDS=14
config = HashForgeConfig.from_env()

# Desde archivo JSON
config = HashForgeConfig.from_json("config.json")

# Programáticamente
config = HashForgeConfig(
    pbkdf2_iterations=200_000,
    bcrypt_rounds=14,
    argon2_time_cost=4
)

# Crear HashManager con configuración
hash_manager = HashManager.from_config(config, "pbkdf2_sha256", "bcrypt")

# Guardar configuración
config.to_json("hash_config.json")
```

### Patrón Builder (Nuevo en v3.0.0)

Crear instancias de HashManager con una API fluida y encadenable:

```python
from hash_forge import HashManager

# Usar patrón builder para configuración elegante
hash_manager = (
    HashManager.builder()
    .with_algorithm("argon2", time_cost=4)
    .with_algorithm("bcrypt", rounds=14)
    .with_algorithm("pbkdf2_sha256", iterations=200_000)
    .with_preferred("argon2")  # Establecer hasher preferido
    .build()
)

# Mezclar hashers preconfigurados con algoritmos
from hash_forge.hashers import PBKDF2Sha256Hasher

custom_hasher = PBKDF2Sha256Hasher(iterations=300_000)
hash_manager = (
    HashManager.builder()
    .with_hasher(custom_hasher)
    .with_algorithm("bcrypt")
    .build()
)
```

## Qué Hay Nuevo en v3.0.0

Hash Forge v3.0.0 representa una reestructuración arquitectónica mayor con mejoras de rendimiento significativas y nuevas características, manteniendo compatibilidad hacia atrás para la API pública.

### 🏗️ Mejoras de Arquitectura
- **Estructura Modular**: Reorganización completa en módulos lógicos (`core/`, `config/`, `utils/`, `hashers/`)
- **Patrón Template Method**: Reducción de 40% en duplicación de código en hashers mediante abstracción de clase base
- **Patrón Auto-Decovery**: Simplificación del registro de hashers con decorador basado en registro automático
- **Chain of Responsibility**: Cada hasher determina autónomamente si puede manejar un hash
- **Clean Architecture**: Separación clara entre API pública e implementación interna

### ⚡ Mejoras de Rendimiento
- **Búsqueda O(1) del Hasher**: Mapeo interno de hashers para detección instantánea del algoritmo (vs iteración O(n))
- **Soporte Async/Await**: API completa async con thread pool executor para tareas CPU-bound
- **Procesamiento por Lotenes**: Procesamiento concurrente de múltiples hashes con `hash_many_async()` y `verify_many_async()`
- **Memoria Optimizada**: Reducción de sobrecarga de creación de objetos y mejor gestión de recursos
- **Eficiencia del Thread Pool**: Uso inteligente de ejecutores asyncio para operaciones de hash paralelas

### 🎯 Nuevas Características
- **Soporte SHA-3**: `sha3_256` y `sha3_512` vía stdlib de Python — sin dependencias extra
- **Rotación de Hash**: `rotate()` para migración segura de algoritmo en el próximo login
- **Inspección de Hash**: `inspect()` devuelve metadatos del algoritmo sin exponer valores raw del hash
- **Listado de Algoritmos**: `list_algorithms()` devuelve algoritmos registrados en una instancia de manager
- **Operaciones Async**: API completa async con `hash_async()`, `verify_async()`, `needs_rehash_async()`
- **Patrón Builder**: API fluida y encadenable para configuración elegante de HashManager
- **Gestión de Configuración**: Cargar ajustes desde variables de entorno, archivos JSON o configuración programática
- **Infraestructura de Logging**: Logging estructurado integrado para depuración y monitoreo
- **Tipado Seguro**: Mejoras en anotaciones de tipos con literales `AlgorithmType` para autocomplete de IDE

### 📊 Benchmarks de Rendimiento
Con operaciones por lotes async, v3.0.0 logra mejoras significativas:
- **10 hashes concurrentes**: ~3-5x más rápido que secuencial
- **100 hashes concurrentes**: ~8-10x más rápido que secuencial
- **Integración con frameworks web**: Operaciones no bloqueantes previenen colas de solicitudes
- **Eficiencia de memoria**: 40% menos duplicación de código = menor footprint de memoria

### 🛠️ Mejora de Experiencia de Desarrollo
- **Tipado Seguro**: Literales `AlgorithmType` para autocomplete de IDE y detección de errores
- **Patrón Factory**: Crear hashers por nombre de algoritmo con `HasherFactory`
- **Patrón Builder**: API encadenable para configuración elegante
- **Métodos de Conveniencia**: `quick_hash()` y `from_algorithms()` para uso más simple
- **Soporte Logging**: Infraestructura de logging integrada para depuración

### 🔐 Mejoras de Seguridad
- **Validación de Parámetros**: Aplica umbrales de seguridad mínimos (150K iteraciones PBKDF2, 12 rondas BCrypt)
- **Excepciones Personalizadas**: Tipos de error más específicos (`InvalidHasherError`, `UnsupportedAlgorithmError`)
- **Configuración Centralizada**: Valores predeterminados de seguridad en un solo lugar
- **Verificación Resistente a Tiempos**: Todos los hashers usan `hmac.compare_digest()` para prevenir ataques de timing

### 🧪 Mejor Testing
- **Suite de Pruebas Mejorada**: 140 pruebas cubriendo toda la funcionalidad
- **Pruebas de Tipado**: Valida uso de `AlgorithmType`
- **Validación de Configuración**: Pruebas de imposición de parámetros de seguridad
- **Pruebas del Patrón Builder**: Valida API fluida
- **Pruebas Async**: Cobertura completa de operaciones async
- **Pruebas de Configuración**: Validación de JSON, variables de entorno y configuración programática

### 📚 Mejoras de API

**Antes de v2.1.0:**
```python
# Creación manual de hashers e importaciones
from hash_forge.hashers.pbkdf2_hasher import PBKDF2Sha256Hasher
hasher = PBKDF2Sha256Hasher(iterations=150000)
hash_manager = HashManager(hasher)
```

**v2.1.0:**
```python
# Simplificado con patrón factory y tipado seguro
from hash_forge import HashManager, AlgorithmType

algorithm: AlgorithmType = "pbkdf2_sha256"  # ¡Autocomplete de IDE!
hash_manager = HashManager.from_algorithms(algorithm)
# o con parámetros personalizados
hashed = HashManager.quick_hash("password", algorithm=algorithm, iterations=200_000)
```

**v3.0.0:**
```python
# Reestructuración completa con builder, config y soporte async
from hash_forge import HashManager
from hash_forge.config import HashForgeConfig

# Patrón builder con API fluida
hash_manager = (
    HashManager.builder()
    .with_algorithm("argon2", time_cost=4, memory_cost=65536)
    .with_algorithm("bcrypt", rounds=14)
    .with_preferred("argon2")
    .build()
)

# Gestión de configuración desde JSON/env
config = HashForgeConfig.from_json("config.json")
hash_manager = HashManager.from_config(config, "argon2", "bcrypt")

# Operaciones async para rendimiento no bloqueante
import asyncio

async def main():
    hashes = await hash_manager.hash_many_async(["pass1", "pass2", "pass3"])
    # ¡3-5x más rápido que hashing secuencial!

asyncio.run(main())
```

### 🔄 Guía de Migración (v2.x → v3.0.0)

La API pública permanece compatible hacia atrás, pero las importaciones internas han cambiado:

**✅ No se requieren cambios** (compatible hacia atrás):
```python
from hash_forge import HashManager, AlgorithmType
from hash_forge.hashers import PBKDF2Sha256Hasher, BCryptHasher

hash_manager = HashManager.from_algorithms("pbkdf2_sha256")
hashed = hash_manager.hash("password")
```

**⚠️ Actualizar si está usando módulos internos** (raros):
```python
# v2.x (desusado)
from hash_forge.protocols import HasherProtocol
from hash_forge.factory import HasherFactory

# v3.0.0 (nuevas rutas)
from hash_forge.core.protocols import HasherProtocol
from hash_forge.core.factory import HasherFactory
```

### 📂 Nueva Estructura de Proyecto

```
hash_forge/
├── __init__.py          # API pública
├── types.py             # Definiciones de tipos (AlgorithmType)
├── exceptions.py        # Clases de excepción
│
├── core/                # Funcionalidad core (interno)
│   ├── manager.py       # Implementación HashManager
│   ├── builder.py       # Patrón builder
│   ├── factory.py       # Hasher factory
│   ├── protocols.py     # Definiciones de protocolo
│   └── base_hasher.py   # Clase base template
│
├── config/              # Configuración (interno)
│   ├── settings.py      # Parámetros predeterminados
│   ├── constants.py     # Constantes
│   └── logging.py       # Configuración logging
│
├── hashers/             # Implementaciones de algoritmos
│   ├── pbkdf2_hasher.py
│   ├── bcrypt_hasher.py
│   ├── argon2_hasher.py
│   ├── sha3_hasher.py
│   └── ...
│
└── utils/               # Utilidades (interno)
    └── helpers.py
```

## Documentación

- **[CHANGELOG.md](CHANGELOG.md)** - Historial de versiones y notas de lanzamiento
- **[SECURITY.md](SECURITY.md)** - Mejores prácticas de seguridad y reporte de vulnerabilidades
- **[CONTRIBUTING.md](CONTRIBUTING.md)** - Guías de contribución y configuración de desarrollo
- **[Examples](examples/)** - Ejemplos de uso práctico

## Contribuir

¡Las contribuciones son bienvenidas! Por favor, lea nuestra [Guía de Contribución](CONTRIBUTING.md) para detalles sobre:

- Configuración del entorno de desarrollo
- Ejecución de pruebas y linting
- Estándares de estilo y documentación
- Envío de pull requests

## Seguridad

Para mejores prácticas de seguridad y reporte de vulnerabilidades, consulte nuestra [Política de Seguridad](SECURITY.md).

**Algoritmos recomendados para hashing de contraseñas:**
1. Argon2 (mejor opción)
2. BCrypt (estándar de la industria)
3. PBKDF2-SHA256 (aprobado por NIST)

## Licencia

Este proyecto está licenciado bajo la Licencia MIT - consulte el archivo [LICENSE](LICENSE) para más detalles.
