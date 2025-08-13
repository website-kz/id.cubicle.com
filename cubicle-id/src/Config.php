<?php
namespace Cubicle;

class Config {
    public static function env(string $key, ?string $default=null): ?string {
        static $loaded = false;
        if (!$loaded) {
            $envFile = __DIR__ . '/../.env';
            if (is_file($envFile)) {
                foreach (file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
                    if (str_starts_with(trim($line), '#')) continue;
                    [$k, $v] = array_pad(explode('=', $line, 2), 2, null);
                    if ($k !== null && $v !== null && getenv($k) === false) {
                        putenv("$k=$v");
                    }
                }
            }
            $loaded = true;
        }
        $val = getenv($key);
        return $val !== false ? $val : $default;
    }
}