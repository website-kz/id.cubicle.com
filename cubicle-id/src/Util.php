<?php
namespace Cubicle;

class Util {
    public static function json(): array {
        $raw = file_get_contents('php://input');
        $data = json_decode($raw, true);
        return is_array($data) ? $data : [];
    }

    public static function now(): string {
        return gmdate('Y-m-d H:i:s');
    }

    public static function clientIP(): string {
        $trust = Config::env('TRUST_PROXY', '0') === '1';
        if ($trust) {
            foreach (['HTTP_X_FORWARDED_FOR','HTTP_X_REAL_IP'] as $h) {
                if (!empty($_SERVER[$h])) {
                    $ip = trim(explode(',', $_SERVER[$h])[0]);
                    if (filter_var($ip, FILTER_VALIDATE_IP)) return $ip;
                }
            }
        }
        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }

    public static function deviceHash(string $imei, string $iccid, string $dns, string $ip): string {
        $pepper = Config::env('PEPPER', 'pepper');
        return hash('sha256', $imei . '|' . $iccid . '|' . $dns . '|' . $ip . '|' . $pepper);
    }

    public static function jsonOut(int $code, array $data): void {
        http_response_code($code);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode($data, JSON_UNESCAPED_UNICODE);
        exit;
    }
}