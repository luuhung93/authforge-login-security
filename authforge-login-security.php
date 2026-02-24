<?php
/*
Plugin Name: AuthForge Login Security
Description: Lightweight TOTP 2FA for wp-login. Includes modal setup with QR and one-time backup codes.
Version: 1.3.2
Author: luuhung93
Author URI: https://github.com/luuhung93
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html
Text Domain: authforge-login-security
Domain Path: /languages
*/

if (!defined('ABSPATH')) {
    exit;
}

define('AUTHFORGE_LOGIN_SECURITY_FILE', __FILE__);

require_once plugin_dir_path(__FILE__) . 'includes/class-authforge-login-security-totp.php';
require_once plugin_dir_path(__FILE__) . 'includes/trait-authforge-login-security-login-turnstile.php';
require_once plugin_dir_path(__FILE__) . 'includes/trait-authforge-login-security-settings.php';
require_once plugin_dir_path(__FILE__) . 'includes/trait-authforge-login-security-profile-ui.php';
require_once plugin_dir_path(__FILE__) . 'includes/trait-authforge-login-security-ajax.php';
require_once plugin_dir_path(__FILE__) . 'includes/class-authforge-login-security-plugin.php';

\AuthForge\LoginSecurity\AuthForge_Login_Security_Plugin::bootstrap();
