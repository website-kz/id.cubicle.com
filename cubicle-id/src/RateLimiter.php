<?php
namespace Cubicle;

use PDO;

class RateLimiter {
    public static function hit(string $bucket, int $perSeconds, int $limit): bool {
        $pdo = DB::pdo();
        $now = time();
        $periodStart = date('Y-m-d H:i:00', $now - ($now % $perSeconds));
        $pdo->beginTransaction();
        try {
            $stmt = $pdo->prepare("SELECT id,counter FROM rate_limiter WHERE bucket=? AND period_start=? FOR UPDATE");
            $stmt->execute([$bucket, $periodStart]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($row) {
                if ((int)$row['counter'] >= $limit) { $pdo->rollBack(); return false; }
                $upd = $pdo->prepare("UPDATE rate_limiter SET counter=counter+1 WHERE id=?");
                $upd->execute([$row['id']]);
            } else {
                $ins = $pdo->prepare("INSERT INTO rate_limiter(bucket, period_start, counter) VALUES(?,?,1)");
                $ins->execute([$bucket, $periodStart]);
            }
            $pdo->commit();
            return true;
        } catch (\Throwable $e) {
            $pdo->rollBack();
            return false;
        }
    }
}