<?php
namespace Cubicle;

class Jwt {
    public static function base64url_encode(string $data): string {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
    public static function base64url_decode(string $data): string {
        $remainder = strlen($data) % 4;
        if ($remainder) $data .= str_repeat('=', 4 - $remainder);
        return base64_decode(strtr($data, '-_', '+/'));
    }

    public static function encode(array $payload, string $secret): string {
        $header = ['typ' => 'JWT', 'alg' => 'HS256'];
        $segments = [
            self::base64url_encode(json_encode($header, JSON_UNESCAPED_UNICODE)),
            self::base64url_encode(json_encode($payload, JSON_UNESCAPED_UNICODE)),
        ];
        $signature = hash_hmac('sha256', implode('.', $segments), $secret, true);
        $segments[] = self::base64url_encode($signature);
        return implode('.', $segments);
    }

    public static function decode(string $jwt, string $secret): ?array {
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) return null;
        [$h, $p, $s] = $parts;
        $sig = self::base64url_decode($s);
        $expected = hash_hmac('sha256', "$h.$p", $secret, true);
        if (!hash_equals($expected, $sig)) return null;
        $payload = json_decode(self::base64url_decode($p), true);
        return $payload ?? null;
    }
}