<?php
/**
 * CONFIGURACIÓN DE BASE DE DATOS
 * Sistema de Login Web Seguro
 */

// Configuración de conexión
define('DB_HOST', 'localhost');
define('DB_USER', 'root');
define('DB_PASS', 'tu_contraseña_mysql');
define('DB_NAME', 'login_db');
define('DB_CHARSET', 'utf8mb4');

// Configuración de seguridad
define('SESSION_TIMEOUT', 3600); // 1 hora en segundos
define('PASSWORD_MIN_LENGTH', 8);
define('MAX_LOGIN_ATTEMPTS', 5);
define('LOCKOUT_TIME', 900); // 15 minutos

// Crear conexión
try {
    $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    
    // Verificar conexión
    if ($conn->connect_error) {
        die("Error de conexión: " . $conn->connect_error);
    }
    
    // Establecer charset
    $conn->set_charset(DB_CHARSET);
    
} catch (Exception $e) {
    die("Error al conectar a la base de datos: " . $e->getMessage());
}

/**
 * FUNCIONES DE SEGURIDAD
 */

/**
 * Hash seguro de contraseña usando bcrypt
 * @param string $password Contraseña a hashear
 * @return string Hash de la contraseña
 */
function hashPassword($password) {
    return password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
}

/**
 * Verificar contraseña
 * @param string $password Contraseña ingresada
 * @param string $hash Hash almacenado
 * @return bool
 */
function verifyPassword($password, $hash) {
    return password_verify($password, $hash);
}

/**
 * Sanitizar entrada
 * @param string $input Entrada a sanitizar
 * @return string
 */
function sanitizeInput($input) {
    return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
}

/**
 * Validar email
 * @param string $email Email a validar
 * @return bool
 */
function validateEmail($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
}

/**
 * Validar username
 * @param string $username Username a validar
 * @return bool
 */
function validateUsername($username) {
    // Solo letras, números, guiones bajos (3-20 caracteres)
    return preg_match('/^[a-zA-Z0-9_]{3,20}$/', $username) === 1;
}

/**
 * Validar contraseña
 * @param string $password Contraseña a validar
 * @return array|bool Array con errores o true si es válida
 */
function validatePassword($password) {
    $errors = [];
    
    if (strlen($password) < PASSWORD_MIN_LENGTH) {
        $errors[] = "La contraseña debe tener al menos " . PASSWORD_MIN_LENGTH . " caracteres";
    }
    
    if (!preg_match('/[A-Z]/', $password)) {
        $errors[] = "La contraseña debe contener al menos una letra mayúscula";
    }
    
    if (!preg_match('/[a-z]/', $password)) {
        $errors[] = "La contraseña debe contener al menos una letra minúscula";
    }
    
    if (!preg_match('/[0-9]/', $password)) {
        $errors[] = "La contraseña debe contener al menos un número";
    }
    
    if (!preg_match('/[!@#$%^&*()_+\-=\[\]{};:"\\|,.<>\/?]/', $password)) {
        $errors[] = "La contraseña debe contener al menos un carácter especial";
    }
    
    return empty($errors) ? true : $errors;
}

/**
 * Generar token seguro
 * @return string
 */
function generateSecureToken() {
    return bin2hex(random_bytes(32));
}

/**
 * Obtener IP del cliente
 * @return string
 */
function getClientIP() {
    if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
        $ip = $_SERVER['HTTP_CLIENT_IP'];
    } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ip = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0];
    } else {
        $ip = $_SERVER['REMOTE_ADDR'];
    }
    return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : 'UNKNOWN';
}

// Iniciar sesión segura
if (session_status() === PHP_SESSION_NONE) {
    session_start([
        'use_strict_mode' => 1,
        'use_cookies' => 1,
        'use_only_cookies' => 1,
        'cookie_httponly' => 1,
        'cookie_secure' => isset($_SERVER['HTTPS']),
        'cookie_samesite' => 'Strict'
    ]);
}

?>
