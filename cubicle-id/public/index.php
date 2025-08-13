<?php
require __DIR__ . '/../vendor/autoload.php';

use Cubicle\AuthController;
use Cubicle\Util;

$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$method = $_SERVER['REQUEST_METHOD'];

function route($method, $path, $cb) {
    global $matched;
    if ($matched) return;
    if ($_SERVER['REQUEST_METHOD'] === $method && preg_match($path, parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH))) {
        $matched = true;
        $cb();
    }
}

$matched = false;

route('POST', '#^/auth/boot$#', fn() => AuthController::boot());
route('POST', '#^/auth/token/refresh$#', fn() => AuthController::refresh());
route('POST', '#^/auth/account/delete$#', fn() => AuthController::deleteAccount());
route('GET',  '#^/me$#', fn() => AuthController::me());

if (!$matched) {
    Util::jsonOut(404, ['error' => 'not_found']);
}