<?php
namespace Cubicle;

use PDO;

class AuthController {

    // 1) Первый запуск / авто-вход (или создание)
    // POST /auth/boot  { imei, iccid, dns, ip?, device_name?, platform? }
    public static function boot(): void {
        $body = Util::json();
        $imei = trim($body['imei'] ?? '');
        $iccid = trim($body['iccid'] ?? '');
        $dns  = trim($body['dns'] ?? '');
        $ip   = trim($body['ip'] ?? '') ?: Util::clientIP();
        $deviceName = trim($body['device_name'] ?? '');
        $platform   = trim($body['platform'] ?? '');

        if (!$imei || !$iccid || !$dns) {
            Util::jsonOut(400, ['error' => 'imei, iccid, dns are required']);
        }

        // rate limit по IP
        if (!RateLimiter::hit('ip:boot:' . Util::clientIP(), 60, 30)) {
            Util::jsonOut(429, ['error' => 'rate_limited']);
        }

        $deviceHash = Util::deviceHash($imei, $iccid, $dns, $ip);
        $pdo = DB::pdo();

        // есть ли такой пользователь?
        $stmt = $pdo->prepare("SELECT * FROM users WHERE device_hash=? LIMIT 1");
        $stmt->execute([$deviceHash]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        // если был удалён и блок ещё активен
        if ($user && $user['status'] !== 'active') {
            $blockUntil = $user['block_until'];
            if ($blockUntil && strtotime($blockUntil) > time()) {
                Util::jsonOut(403, [
                    'error' => 'blocked',
                    'block_until' => $blockUntil
                ]);
            }
            // если удалён и блок истёк — можно реанимировать аккаунт
            if ($user['status'] !== 'active') {
                $upd = $pdo->prepare("UPDATE users SET status='active', deleted_at=NULL, block_until=NULL WHERE id=?");
                $upd->execute([$user['id']]);
                $user['status'] = 'active';
            }
        }

        // если нет пользователя — создаём (один аккаунт на человека = один device_hash)
        if (!$user) {
            $ins = $pdo->prepare("
                INSERT INTO users(device_hash, device_name, platform)
                VALUES(?,?,?)
            ");
            $ins->execute([$deviceHash, $deviceName ?: null, $platform ?: null]);
            $userId = (int)$pdo->lastInsertId();
            $stmt = $pdo->prepare("SELECT * FROM users WHERE id=?");
            $stmt->execute([$userId]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
        }

        // выдаём токены
        [$access, $exp] = self::issueAccess((int)$user['id']);
        $refresh = self::issueRefresh((int)$user['id'], $deviceHash);

        Util::jsonOut(200, [
            'user_id' => (int)$user['id'],
            'access_token' => $access,
            'access_expires_at' => gmdate('c', $exp),
            'refresh_token' => $refresh,
            'status' => $user['status'],
        ]);
    }

    // 2) Обновить access по refresh
    // POST /auth/token/refresh { refresh_token }
    public static function refresh(): void {
        $body = Util::json();
        $refresh = $body['refresh_token'] ?? '';
        if (!$refresh) Util::jsonOut(400, ['error' => 'refresh_token required']);

        $pepper = Config::env('PEPPER', 'pepper');
        $rtHash = hash('sha256', $refresh . $pepper);
        $pdo = DB::pdo();

        $stmt = $pdo->prepare("SELECT * FROM refresh_tokens WHERE rt_hash=? LIMIT 1");
        $stmt->execute([$rtHash]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$row || (int)$row['revoked'] === 1 || strtotime($row['expires_at']) < time()) {
            Util::jsonOut(401, ['error' => 'invalid_refresh']);
        }

        // access
        [$access, $exp] = self::issueAccess((int)$row['user_id']);
        Util::jsonOut(200, [
            'access_token' => $access,
            'access_expires_at' => gmdate('c', $exp),
        ]);
    }

    // 3) Удалить текущий аккаунт (вместо logout)
    // POST /auth/account/delete  (Authorization: Bearer <access>)
    public static function deleteAccount(): void {
        $userId = self::requireUser();
        $pdo = DB::pdo();

        // блокируем возможность моментально зарегаться снова
        $days = (int)Config::env('BLOCK_DAYS_AFTER_DELETE', '30');
        $stmt = $pdo->prepare("UPDATE users SET status='deleted', deleted_at=NOW(), block_until=DATE_ADD(NOW(), INTERVAL ? DAY) WHERE id=?");
        $stmt->execute([$days, $userId]);

        // ревок всех refresh токенов юзера
        $rev = $pdo->prepare("UPDATE refresh_tokens SET revoked=1 WHERE user_id=?");
        $rev->execute([$userId]);

        Util::jsonOut(200, ['ok' => true, 'message' => 'account_deleted', 'blocked_days' => $days]);
    }

    // 4) Профиль
    // GET /me  (Authorization: Bearer <access>)
    public static function me(): void {
        $userId = self::requireUser();
        $pdo = DB::pdo();
        $stmt = $pdo->prepare("SELECT id, device_name, platform, status, created_at, deleted_at, block_until FROM users WHERE id=?");
        $stmt->execute([$userId]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$user) Util::jsonOut(404, ['error' => 'not_found']);
        Util::jsonOut(200, ['user' => $user]);
    }

    // ===== helpers =====

    private static function issueAccess(int $userId): array {
        $ttl = (int)Config::env('ACCESS_TTL_SECONDS', '600');
        $now = time();
        $payload = [
            'sub' => $userId,
            'iat' => $now,
            'exp' => $now + $ttl,
            'iss' => 'cubicle-id',
            'typ' => 'access'
        ];
        $jwt = Jwt::encode($payload, Config::env('JWT_SECRET'));
        return [$jwt, $payload['exp']];
    }

    private static function issueRefresh(int $userId, string $deviceHash): string {
        $ttl = (int)Config::env('REFRESH_TTL_SECONDS', '2592000');
        $token = bin2hex(random_bytes(32)); // 64 hex chars
        $pepper = Config::env('PEPPER', 'pepper');
        $rtHash = hash('sha256', $token . $pepper);

        $pdo = DB::pdo();
        $stmt = $pdo->prepare("INSERT INTO refresh_tokens(user_id, device_hash, rt_hash, expires_at) VALUES(?, ?, ?, DATE_ADD(NOW(), INTERVAL ? SECOND))");
        $stmt->execute([$userId, $deviceHash, $rtHash, $ttl]);
        return $token;
    }

    private static function bearer(): ?string {
        $hdr = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
        if (stripos($hdr, 'Bearer ') === 0) return trim(substr($hdr, 7));
        return null;
    }

    private static function requireUser(): int {
        $token = self::bearer();
        if (!$token) Util::jsonOut(401, ['error' => 'no_token']);
        $payload = Jwt::decode($token, Config::env('JWT_SECRET'));
        if (!$payload || ($payload['exp'] ?? 0) < time() || ($payload['typ'] ?? '') !== 'access') {
            Util::jsonOut(401, ['error' => 'invalid_token']);
        }
        return (int)$payload['sub'];
    }
}