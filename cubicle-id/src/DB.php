<?php
namespace Cubicle;

use PDO;
use PDOException;

class DB {
    public static function pdo(): PDO {
        static $pdo = null;
        if ($pdo) return $pdo;
        $dsn  = Config::env('DB_DSN');
        $user = Config::env('DB_USER');
        $pass = Config::env('DB_PASS');
        $pdo = new PDO($dsn, $user, $pass, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        ]);
        return $pdo;
    }
}