<?php
namespace AuthForge\LoginSecurity;

if (!defined('ABSPATH')) {
    exit;
}

trait AuthForge_Login_Security_Login_Turnstile_Trait {
    public function render_login_field() {
        $turnstile_site_key = $this->get_turnstile_site_key();
        if ($turnstile_site_key !== '' && $this->is_turnstile_enabled()) :
            ?>
        <div class="authforge-login-security-turnstile">
            <div class="cf-turnstile" data-sitekey="<?php echo esc_attr($turnstile_site_key); ?>"></div>
        </div>
            <?php
        endif;
    }

    public function enqueue_login_assets() {
        if (!$this->is_turnstile_enabled()) {
            return;
        }

        $base_url = plugin_dir_url(\AUTHFORGE_LOGIN_SECURITY_FILE) . 'assets/';
        $base_path = plugin_dir_path(\AUTHFORGE_LOGIN_SECURITY_FILE) . 'assets/';

        wp_enqueue_style(
            'authforge-login-security-login',
            $base_url . 'login.css',
            array(),
            $this->get_asset_version($base_path . 'login.css')
        );

        wp_enqueue_script(
            'authforge-login-security-turnstile',
            'https://challenges.cloudflare.com/turnstile/v0/api.js',
            array(),
            null,
            true
        );
    }

    public function validate_turnstile_login($user, $username, $password) {
        if (!$this->is_wp_login_submission() || !$this->is_turnstile_enabled()) {
            return $user;
        }

        $token = isset($_POST['cf-turnstile-response']) ? sanitize_text_field(wp_unslash($_POST['cf-turnstile-response'])) : '';
        if ($token === '') {
            return new \WP_Error('authforge_login_security_turnstile_missing', __('Please complete the security check.', 'authforge-login-security'));
        }

        if (!$this->verify_turnstile_token($token)) {
            return new \WP_Error('authforge_login_security_turnstile_invalid', __('Security check failed. Please try again.', 'authforge-login-security'));
        }

        return $user;
    }

    public function validate_login_otp($user, $username, $password) {
        if (!($user instanceof \WP_User)) {
            return $user;
        }

        if (!$this->is_wp_login_submission()) {
            return $user;
        }

        if (!$this->is_enabled_for_user($user->ID)) {
            return $user;
        }

        $this->start_login_otp_challenge($user);
        return $user;
    }

    public function handle_login_otp_challenge() {
        $token = $this->get_login_otp_token();
        $challenge = $this->get_login_otp_challenge($token);

        if (!is_array($challenge) || empty($challenge['user_id'])) {
            $this->render_login_otp_screen(
                new \WP_Error('authforge_login_security_invalid_challenge', __('Your verification session is invalid or expired. Please login again.', 'authforge-login-security')),
                $token
            );
            exit;
        }

        $user = get_user_by('id', (int) $challenge['user_id']);
        if (!($user instanceof \WP_User)) {
            $this->delete_login_otp_challenge($token);
            $this->render_login_otp_screen(
                new \WP_Error('authforge_login_security_invalid_user', __('User not found. Please login again.', 'authforge-login-security')),
                $token
            );
            exit;
        }

        if (!$this->is_enabled_for_user($user->ID)) {
            $this->delete_login_otp_challenge($token);
            $this->render_login_otp_screen(
                new \WP_Error('authforge_login_security_disabled', __('Two-factor authentication is disabled for this account. Please login again.', 'authforge-login-security')),
                $token
            );
            exit;
        }

        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            if (!$this->is_valid_login_otp_nonce($token)) {
                $this->render_login_otp_screen(
                    new \WP_Error('authforge_login_security_invalid_nonce', __('Security check failed. Please login again.', 'authforge-login-security')),
                    $token
                );
                exit;
            }

            $otp = $this->get_submitted_otp();
            if ($otp === '') {
                $this->render_login_otp_screen(
                    new \WP_Error('authforge_login_security_missing_otp', __('Authentication code is required.', 'authforge-login-security')),
                    $token
                );
                exit;
            }

            $result = $this->validate_user_otp_input($user, $otp);
            if ($result instanceof \WP_User) {
                $this->complete_login_otp_challenge($result, $challenge, $token);
                exit;
            }

            $this->render_login_otp_screen($result, $token);
            exit;
        }

        $this->render_login_otp_screen(null, $token);
        exit;
    }

    private function validate_user_otp_input(\WP_User $user, $otp) {
        $secret = (string) get_user_meta($user->ID, AuthForge_Login_Security_Plugin::META_SECRET, true);
        if ($secret === '') {
            return new \WP_Error('authforge_login_security_missing_secret', __('Two-factor is enabled but not configured for this account.', 'authforge-login-security'));
        }

        if ($this->is_totp_input($otp) && $this->verify_totp($user->ID, $secret, $otp)) {
            return $user;
        }

        if ($this->consume_backup_code($user->ID, $otp)) {
            return $user;
        }

        return new \WP_Error('authforge_login_security_invalid_otp', __('Invalid authentication or backup code.', 'authforge-login-security'));
    }

    private function verify_turnstile_token($token) {
        $secret = $this->get_turnstile_secret_key();
        return $this->verify_turnstile_token_with_secret($token, $secret);
    }

    private function verify_turnstile_token_with_secret($token, $secret) {
        if ($secret === '') {
            return false;
        }

        $response = wp_remote_post(
            'https://challenges.cloudflare.com/turnstile/v0/siteverify',
            array(
                'timeout' => 8,
                'body' => array(
                    'secret' => $secret,
                    'response' => $token,
                    'remoteip' => $this->get_client_ip(),
                ),
            )
        );

        if (is_wp_error($response)) {
            return false;
        }

        $status_code = (int) wp_remote_retrieve_response_code($response);
        if ($status_code !== 200) {
            return false;
        }

        $body = wp_remote_retrieve_body($response);
        $payload = json_decode($body, true);

        return is_array($payload) && !empty($payload['success']);
    }

    private function get_client_ip() {
        if (isset($_SERVER['REMOTE_ADDR'])) {
            return sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR']));
        }

        return '';
    }

    private function get_turnstile_site_key() {
        return (string) get_option(AuthForge_Login_Security_Plugin::OPTION_TURNSTILE_SITE_KEY, '');
    }

    private function get_turnstile_secret_key() {
        return (string) get_option(AuthForge_Login_Security_Plugin::OPTION_TURNSTILE_SECRET_KEY, '');
    }

    private function is_turnstile_enabled() {
        if (get_option(AuthForge_Login_Security_Plugin::OPTION_TURNSTILE_ENABLED, '0') !== '1') {
            return false;
        }

        return $this->get_turnstile_site_key() !== '' && $this->get_turnstile_secret_key() !== '';
    }

    private function get_submitted_otp($field = AuthForge_Login_Security_Plugin::REQUEST_KEY_OTP) {
        return isset($_POST[$field]) ? trim(sanitize_text_field(wp_unslash($_POST[$field]))) : '';
    }

    private function is_totp_input($otp) {
        return preg_match('/^\d{6}$/', $otp) === 1;
    }

    private function is_wp_login_submission() {
        global $pagenow;

        if ($pagenow !== 'wp-login.php') {
            return false;
        }

        return isset($_POST['log'], $_POST['pwd']);
    }

    private function verify_totp($user_id, $secret, $otp) {
        $window = (int) apply_filters('authforge_login_security_window', 1, $user_id);
        if ($window < 0) {
            $window = 0;
        }

        return $this->totp->verify_for_login($user_id, $secret, $otp, $window);
    }

    private function verify_totp_code_only($secret, $otp) {
        return $this->totp->verify_code_only($secret, $otp, 1);
    }

    private function start_login_otp_challenge(\WP_User $user) {
        $token = wp_generate_password(32, false, false);
        $challenge = array(
            'user_id' => (int) $user->ID,
            'remember' => $this->should_remember_login() ? 1 : 0,
            'redirect_to' => $this->get_requested_redirect(),
            'created' => time(),
        );

        set_transient(
            $this->get_login_otp_transient_key($token),
            $challenge,
            AuthForge_Login_Security_Plugin::LOGIN_OTP_TTL
        );

        wp_safe_redirect($this->get_login_otp_url($token));
        exit;
    }

    private function complete_login_otp_challenge(\WP_User $user, array $challenge, $token) {
        $this->delete_login_otp_challenge($token);
        wp_clear_auth_cookie();
        wp_set_current_user($user->ID);
        wp_set_auth_cookie($user->ID, !empty($challenge['remember']), is_ssl());
        do_action('wp_login', $user->user_login, $user);

        wp_safe_redirect($this->normalize_redirect_to($challenge['redirect_to']));
    }

    private function render_login_otp_screen($error, $token) {
        $errors = new \WP_Error();
        if ($error instanceof \WP_Error) {
            $errors = $error;
        }

        login_header(__('Two-Factor Authentication', 'authforge-login-security'), '', $errors);
        ?>
        <form method="post" action="<?php echo esc_url($this->get_login_otp_url($token)); ?>">
            <?php wp_nonce_field($this->get_login_otp_nonce_action($token), 'authforge_login_security_otp_nonce'); ?>
            <p>
                <label for="<?php echo esc_attr(AuthForge_Login_Security_Plugin::REQUEST_KEY_OTP); ?>"><?php esc_html_e('Authentication code', 'authforge-login-security'); ?><br />
                    <input type="text" name="<?php echo esc_attr(AuthForge_Login_Security_Plugin::REQUEST_KEY_OTP); ?>" id="<?php echo esc_attr(AuthForge_Login_Security_Plugin::REQUEST_KEY_OTP); ?>" class="input" value="" size="20" inputmode="numeric" autocomplete="one-time-code" />
                </label>
            </p>
            <p class="submit">
                <input type="submit" class="button button-primary button-large" value="<?php esc_attr_e('Verify', 'authforge-login-security'); ?>" />
            </p>
            <p class="forgetmenot">
                <a href="<?php echo esc_url(wp_login_url()); ?>"><?php esc_html_e('Back to login', 'authforge-login-security'); ?></a>
            </p>
        </form>
        <?php
        login_footer();
    }

    private function get_login_otp_url($token) {
        $url = add_query_arg('action', AuthForge_Login_Security_Plugin::LOGIN_ACTION_OTP, wp_login_url());
        if ($token === '') {
            return $url;
        }
        return add_query_arg(AuthForge_Login_Security_Plugin::REQUEST_KEY_LOGIN_TOKEN, rawurlencode($token), $url);
    }

    private function get_login_otp_token() {
        if (isset($_REQUEST[AuthForge_Login_Security_Plugin::REQUEST_KEY_LOGIN_TOKEN])) {
            $token = sanitize_text_field(wp_unslash($_REQUEST[AuthForge_Login_Security_Plugin::REQUEST_KEY_LOGIN_TOKEN]));
            return preg_replace('/[^a-zA-Z0-9]/', '', $token);
        }

        return '';
    }

    private function get_login_otp_challenge($token) {
        if ($token === '') {
            return null;
        }

        $data = get_transient($this->get_login_otp_transient_key($token));
        return is_array($data) ? $data : null;
    }

    private function delete_login_otp_challenge($token) {
        if ($token !== '') {
            delete_transient($this->get_login_otp_transient_key($token));
        }
    }

    private function get_login_otp_transient_key($token) {
        return AuthForge_Login_Security_Plugin::LOGIN_OTP_TRANSIENT_PREFIX . $token;
    }

    private function should_remember_login() {
        return isset($_POST['rememberme']) && (string) wp_unslash($_POST['rememberme']) === 'forever';
    }

    private function get_requested_redirect() {
        $redirect = isset($_REQUEST['redirect_to']) ? wp_unslash($_REQUEST['redirect_to']) : '';
        return $this->normalize_redirect_to($redirect);
    }

    private function normalize_redirect_to($redirect) {
        $redirect = is_string($redirect) ? trim($redirect) : '';
        if ($redirect === '') {
            return admin_url();
        }

        return wp_validate_redirect($redirect, admin_url());
    }

    private function get_login_otp_nonce_action($token) {
        return 'authforge_login_security_login_otp_' . $token;
    }

    private function is_valid_login_otp_nonce($token) {
        $nonce = isset($_POST['authforge_login_security_otp_nonce']) ? sanitize_text_field(wp_unslash($_POST['authforge_login_security_otp_nonce'])) : '';
        if ($nonce === '') {
            return false;
        }

        return wp_verify_nonce($nonce, $this->get_login_otp_nonce_action($token)) === 1;
    }
}
