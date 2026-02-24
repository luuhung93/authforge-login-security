<?php
namespace AuthForge\LoginSecurity;

if (!defined('ABSPATH')) {
    exit;
}

trait AuthForge_Login_Security_Ajax_Trait {
    private function get_ajax_user_id_or_error() {
        if (!$this->is_valid_ajax_post_request()) {
            wp_send_json_error(array('message' => __('Invalid request method.', 'authforge-login-security')), 405);
        }

        $user_id = isset($_POST['user_id']) ? absint($_POST['user_id']) : 0;
        if ($this->can_manage_user_2fa($user_id)) {
            return $user_id;
        }

        wp_send_json_error(array('message' => __('Not allowed.', 'authforge-login-security')), 403);
        return 0;
    }

    public function ajax_start_setup() {
        $user_id = $this->get_ajax_user_id_or_error();
        if ($user_id <= 0) {
            return;
        }

        $secret = $this->totp->generate_secret();
        update_user_meta($user_id, AuthForge_Login_Security_Plugin::META_PENDING_SECRET, $secret);
        update_user_meta($user_id, AuthForge_Login_Security_Plugin::META_PENDING_CREATED, time());

        $user = get_userdata($user_id);
        if (!($user instanceof \WP_User)) {
            wp_send_json_error(array('message' => __('User not found.', 'authforge-login-security')), 404);
        }

        $otpauth_uri = $this->totp->build_otpauth_uri($user, $secret);

        wp_send_json_success(array(
            'secret' => $secret,
            'otpauthUri' => $otpauth_uri,
        ));
    }

    public function ajax_confirm_setup() {
        $user_id = $this->get_ajax_user_id_or_error();
        if ($user_id <= 0) {
            return;
        }

        $otp = $this->get_submitted_otp('otp');
        if (!preg_match('/^\d{6}$/', $otp)) {
            wp_send_json_error(array('message' => __('Please enter a valid 6-digit code.', 'authforge-login-security')), 400);
        }

        $secret = (string) get_user_meta($user_id, AuthForge_Login_Security_Plugin::META_PENDING_SECRET, true);
        $created = (int) get_user_meta($user_id, AuthForge_Login_Security_Plugin::META_PENDING_CREATED, true);

        if ($secret === '' || $created <= 0 || (time() - $created) > AuthForge_Login_Security_Plugin::PENDING_TTL) {
            delete_user_meta($user_id, AuthForge_Login_Security_Plugin::META_PENDING_SECRET);
            delete_user_meta($user_id, AuthForge_Login_Security_Plugin::META_PENDING_CREATED);
            wp_send_json_error(array('message' => __('Setup expired. Start again.', 'authforge-login-security')), 400);
        }

        if (!$this->verify_totp_code_only($secret, $otp)) {
            wp_send_json_error(array('message' => __('Invalid authentication code.', 'authforge-login-security')), 400);
        }

        update_user_meta($user_id, AuthForge_Login_Security_Plugin::META_SECRET, $secret);
        update_user_meta($user_id, AuthForge_Login_Security_Plugin::META_ENABLED, '1');
        delete_user_meta($user_id, AuthForge_Login_Security_Plugin::META_PENDING_SECRET);
        delete_user_meta($user_id, AuthForge_Login_Security_Plugin::META_PENDING_CREATED);
        delete_user_meta($user_id, AuthForge_Login_Security_Plugin::META_LAST_COUNTER);

        $backup_codes = $this->generate_backup_codes();
        $this->store_backup_codes($user_id, $backup_codes);

        wp_send_json_success(array(
            'backupCodes' => $backup_codes,
            'backupCount' => count($backup_codes),
        ));
    }

    public function ajax_regenerate_backup_codes() {
        $user_id = $this->get_ajax_user_id_or_error();
        if ($user_id <= 0) {
            return;
        }

        if (!$this->is_enabled_for_user($user_id)) {
            wp_send_json_error(array('message' => __('2FA is not enabled for this user.', 'authforge-login-security')), 400);
        }

        $backup_codes = $this->generate_backup_codes();
        $this->store_backup_codes($user_id, $backup_codes);

        wp_send_json_success(array(
            'backupCodes' => $backup_codes,
            'backupCount' => count($backup_codes),
        ));
    }

    public function ajax_disable_2fa() {
        $user_id = $this->get_ajax_user_id_or_error();
        if ($user_id <= 0) {
            return;
        }

        update_user_meta($user_id, AuthForge_Login_Security_Plugin::META_ENABLED, '0');
        delete_user_meta($user_id, AuthForge_Login_Security_Plugin::META_SECRET);
        delete_user_meta($user_id, AuthForge_Login_Security_Plugin::META_PENDING_SECRET);
        delete_user_meta($user_id, AuthForge_Login_Security_Plugin::META_PENDING_CREATED);
        delete_user_meta($user_id, AuthForge_Login_Security_Plugin::META_LAST_COUNTER);
        delete_user_meta($user_id, AuthForge_Login_Security_Plugin::META_BACKUP_CODES);

        wp_send_json_success(array('backupCount' => 0));
    }

    private function can_manage_user_2fa($user_id) {
        if ($user_id <= 0 || !current_user_can('edit_user', $user_id)) {
            return false;
        }

        $nonce_result = check_ajax_referer($this->get_manage_nonce_action($user_id), 'nonce', false);
        if ($nonce_result !== 1 && $nonce_result !== 2) {
            return false;
        }

        return true;
    }

    private function get_manage_nonce_action($user_id) {
        return AuthForge_Login_Security_Plugin::NONCE_MANAGE_PREFIX . (int) $user_id;
    }

    private function is_valid_ajax_post_request() {
        if (!wp_doing_ajax()) {
            return false;
        }

        $request_method = isset($_SERVER['REQUEST_METHOD']) ? strtoupper(sanitize_text_field(wp_unslash($_SERVER['REQUEST_METHOD']))) : '';
        return $request_method === 'POST';
    }
}
