<?php
namespace AuthForge\LoginSecurity;

if (!defined('ABSPATH')) {
    exit;
}

final class AuthForge_Login_Security_TOTP {
    public function verify_for_login($user_id, $secret, $otp, $window) {
        $key = $this->base32_decode($secret);
        if ($key === false || $key === '') {
            return false;
        }

        $counter = (int) floor(time() / 30);
        $last_counter = (int) get_user_meta($user_id, AuthForge_Login_Security_Plugin::META_LAST_COUNTER, true);

        for ($offset = -$window; $offset <= $window; $offset++) {
            $slot = $counter + $offset;
            if ($slot <= $last_counter) {
                continue;
            }

            $expected = str_pad((string) $this->hotp($key, $slot), 6, '0', STR_PAD_LEFT);
            if (hash_equals($expected, $otp)) {
                update_user_meta($user_id, AuthForge_Login_Security_Plugin::META_LAST_COUNTER, $slot);
                return true;
            }
        }

        return false;
    }

    public function verify_code_only($secret, $otp, $window) {
        $key = $this->base32_decode($secret);
        if ($key === false || $key === '') {
            return false;
        }

        $counter = (int) floor(time() / 30);

        for ($offset = -$window; $offset <= $window; $offset++) {
            $slot = $counter + $offset;
            $expected = str_pad((string) $this->hotp($key, $slot), 6, '0', STR_PAD_LEFT);
            if (hash_equals($expected, $otp)) {
                return true;
            }
        }

        return false;
    }

    public function generate_secret() {
        $bytes = random_bytes(20);
        return $this->base32_encode($bytes);
    }

    public function build_otpauth_uri(\WP_User $user, $secret) {
        $site_name = wp_specialchars_decode(get_bloginfo('name'), ENT_QUOTES);
        $host = wp_parse_url(home_url(), PHP_URL_HOST);
        $account_name = $user->user_login . '@' . $host;

        $label = rawurlencode($site_name . ':' . $account_name);
        $issuer = rawurlencode($site_name);

        return 'otpauth://totp/' . $label . '?secret=' . rawurlencode($secret) . '&issuer=' . $issuer . '&digits=6&period=30';
    }

    private function hotp($secret, $counter) {
        $binary_counter = pack('N2', 0, $counter);
        $hash = hash_hmac('sha1', $binary_counter, $secret, true);
        $offset = ord(substr($hash, -1)) & 0x0F;
        $part = substr($hash, $offset, 4);
        $value = unpack('N', $part);
        $value = $value[1] & 0x7FFFFFFF;
        return $value % 1000000;
    }

    private function base32_encode($binary) {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $bits = '';
        $encoded = '';
        $length = strlen($binary);

        for ($i = 0; $i < $length; $i++) {
            $bits .= str_pad(decbin(ord($binary[$i])), 8, '0', STR_PAD_LEFT);
        }

        $chunks = str_split($bits, 5);
        foreach ($chunks as $chunk) {
            if (strlen($chunk) < 5) {
                $chunk = str_pad($chunk, 5, '0', STR_PAD_RIGHT);
            }
            $encoded .= $alphabet[bindec($chunk)];
        }

        return $encoded;
    }

    private function base32_decode($input) {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $input = strtoupper(preg_replace('/[^A-Z2-7]/', '', $input));
        if ($input === '') {
            return false;
        }

        $bits = '';
        $length = strlen($input);

        for ($i = 0; $i < $length; $i++) {
            $value = strpos($alphabet, $input[$i]);
            if ($value === false) {
                return false;
            }
            $bits .= str_pad(decbin($value), 5, '0', STR_PAD_LEFT);
        }

        $bytes = str_split($bits, 8);
        $decoded = '';

        foreach ($bytes as $byte) {
            if (strlen($byte) < 8) {
                continue;
            }
            $decoded .= chr(bindec($byte));
        }

        return $decoded;
    }
}
