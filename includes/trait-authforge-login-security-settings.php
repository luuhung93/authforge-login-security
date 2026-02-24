<?php
namespace AuthForge\LoginSecurity;

if (!defined('ABSPATH')) {
    exit;
}

trait AuthForge_Login_Security_Settings_Trait {
    public function enqueue_settings_assets($hook_suffix) {
        if ($hook_suffix !== 'settings_page_' . AuthForge_Login_Security_Plugin::SETTINGS_PAGE_SLUG) {
            return;
        }

        if (!current_user_can('manage_options')) {
            return;
        }

        $base_url = plugin_dir_url(\AUTHFORGE_LOGIN_SECURITY_FILE) . 'assets/';
        $base_path = plugin_dir_path(\AUTHFORGE_LOGIN_SECURITY_FILE) . 'assets/';

        wp_enqueue_style(
            'authforge-login-security-admin',
            $base_url . 'admin.css',
            array(),
            $this->get_asset_version($base_path . 'admin.css')
        );

        wp_enqueue_script(
            'authforge-login-security-turnstile-api',
            'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit',
            array(),
            null,
            true
        );

        wp_enqueue_script(
            'authforge-login-security-settings',
            $base_url . 'settings.js',
            array('authforge-login-security-turnstile-api'),
            $this->get_asset_version($base_path . 'settings.js'),
            true
        );

        wp_localize_script('authforge-login-security-settings', 'AuthForgeLoginSecuritySettings', array(
            'ajaxUrl' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce(AuthForge_Login_Security_Plugin::NONCE_TURNSTILE_TEST),
            'actionTestTurnstile' => AuthForge_Login_Security_Plugin::AJAX_ACTION_TEST_TURNSTILE,
            'i18n' => $this->get_settings_i18n_strings(),
        ));
    }

    public function register_settings_page() {
        add_options_page(
            __('AuthForge Login Security', 'authforge-login-security'),
            __('AuthForge Login Security', 'authforge-login-security'),
            'manage_options',
            AuthForge_Login_Security_Plugin::SETTINGS_PAGE_SLUG,
            array($this, 'render_settings_page')
        );
    }

    public function register_settings() {
        register_setting(
            AuthForge_Login_Security_Plugin::SETTINGS_GROUP,
            AuthForge_Login_Security_Plugin::OPTION_TURNSTILE_ENABLED,
            array($this, 'sanitize_checkbox')
        );
        register_setting(
            AuthForge_Login_Security_Plugin::SETTINGS_GROUP,
            AuthForge_Login_Security_Plugin::OPTION_TURNSTILE_SITE_KEY,
            'sanitize_text_field'
        );
        register_setting(
            AuthForge_Login_Security_Plugin::SETTINGS_GROUP,
            AuthForge_Login_Security_Plugin::OPTION_TURNSTILE_SECRET_KEY,
            'sanitize_text_field'
        );

        add_settings_section(
            AuthForge_Login_Security_Plugin::SETTINGS_SECTION_TURNSTILE,
            __('Cloudflare Turnstile', 'authforge-login-security'),
            '__return_false',
            AuthForge_Login_Security_Plugin::SETTINGS_PAGE_SLUG
        );

        add_settings_field(
            'authforge_login_security_turnstile_enabled',
            __('Enable Turnstile on Login', 'authforge-login-security'),
            array($this, 'render_turnstile_enabled_field'),
            AuthForge_Login_Security_Plugin::SETTINGS_PAGE_SLUG,
            AuthForge_Login_Security_Plugin::SETTINGS_SECTION_TURNSTILE
        );
        add_settings_field(
            'authforge_login_security_turnstile_site_key',
            __('Turnstile Site Key', 'authforge-login-security'),
            array($this, 'render_turnstile_site_key_field'),
            AuthForge_Login_Security_Plugin::SETTINGS_PAGE_SLUG,
            AuthForge_Login_Security_Plugin::SETTINGS_SECTION_TURNSTILE
        );
        add_settings_field(
            'authforge_login_security_turnstile_secret_key',
            __('Turnstile Secret Key', 'authforge-login-security'),
            array($this, 'render_turnstile_secret_key_field'),
            AuthForge_Login_Security_Plugin::SETTINGS_PAGE_SLUG,
            AuthForge_Login_Security_Plugin::SETTINGS_SECTION_TURNSTILE
        );
        add_settings_field(
            'authforge_login_security_turnstile_test',
            __('Turnstile Test', 'authforge-login-security'),
            array($this, 'render_turnstile_test_field'),
            AuthForge_Login_Security_Plugin::SETTINGS_PAGE_SLUG,
            AuthForge_Login_Security_Plugin::SETTINGS_SECTION_TURNSTILE
        );
    }

    public function render_settings_page() {
        if (!current_user_can('manage_options')) {
            return;
        }
        ?>
        <div class="wrap">
            <h1><?php esc_html_e('AuthForge Login Security Settings', 'authforge-login-security'); ?></h1>
            <form method="post" action="options.php">
                <?php settings_fields(AuthForge_Login_Security_Plugin::SETTINGS_GROUP); ?>
                <?php do_settings_sections(AuthForge_Login_Security_Plugin::SETTINGS_PAGE_SLUG); ?>
                <?php submit_button(); ?>
            </form>
            <?php $this->render_turnstile_test_modal(); ?>
        </div>
        <?php
    }

    public function render_turnstile_enabled_field() {
        $enabled = get_option(AuthForge_Login_Security_Plugin::OPTION_TURNSTILE_ENABLED, '0') === '1';
        ?>
        <label>
            <input type="hidden" name="<?php echo esc_attr(AuthForge_Login_Security_Plugin::OPTION_TURNSTILE_ENABLED); ?>" value="0" />
            <input type="checkbox" name="<?php echo esc_attr(AuthForge_Login_Security_Plugin::OPTION_TURNSTILE_ENABLED); ?>" value="1" <?php checked($enabled); ?> />
            <?php esc_html_e('Require Turnstile challenge on wp-login.php before authentication.', 'authforge-login-security'); ?>
        </label>
        <?php
    }

    public function render_turnstile_site_key_field() {
        $value = $this->get_turnstile_site_key();
        ?>
        <input type="text" class="regular-text" id="authforge-login-security-turnstile-site-key" name="<?php echo esc_attr(AuthForge_Login_Security_Plugin::OPTION_TURNSTILE_SITE_KEY); ?>" value="<?php echo esc_attr($value); ?>" />
        <?php
    }

    public function render_turnstile_secret_key_field() {
        $value = $this->get_turnstile_secret_key();
        ?>
        <input type="password" class="regular-text" id="authforge-login-security-turnstile-secret-key" name="<?php echo esc_attr(AuthForge_Login_Security_Plugin::OPTION_TURNSTILE_SECRET_KEY); ?>" value="<?php echo esc_attr($value); ?>" autocomplete="off" />
        <?php
    }

    public function render_turnstile_test_field() {
        ?>
        <button type="button" class="button" id="authforge-login-security-test-turnstile">
            <?php esc_html_e('Open Turnstile Test', 'authforge-login-security'); ?>
        </button>
        <p class="description">
            <?php esc_html_e('Use current Site Key and Secret Key values to run a live Turnstile verification test in a popup.', 'authforge-login-security'); ?>
        </p>
        <?php
    }

    public function ajax_test_turnstile() {
        $request_method = isset($_SERVER['REQUEST_METHOD']) ? strtoupper(sanitize_text_field(wp_unslash($_SERVER['REQUEST_METHOD']))) : '';
        if (!wp_doing_ajax() || $request_method !== 'POST') {
            wp_send_json_error(array('message' => __('Invalid request method.', 'authforge-login-security')), 405);
        }

        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => __('Not allowed.', 'authforge-login-security')), 403);
        }

        $nonce_result = check_ajax_referer(AuthForge_Login_Security_Plugin::NONCE_TURNSTILE_TEST, 'nonce', false);
        if ($nonce_result !== 1 && $nonce_result !== 2) {
            wp_send_json_error(array('message' => __('Invalid security token.', 'authforge-login-security')), 403);
        }

        $token = isset($_POST['token']) ? sanitize_text_field(wp_unslash($_POST['token'])) : '';
        $secret_key = isset($_POST['secretKey']) ? sanitize_text_field(wp_unslash($_POST['secretKey'])) : '';

        if ($token === '' || $secret_key === '') {
            wp_send_json_error(array('message' => __('Missing token or secret key.', 'authforge-login-security')), 400);
        }

        if (!$this->verify_turnstile_token_with_secret($token, $secret_key)) {
            wp_send_json_error(array('message' => __('Turnstile verification failed. Check Site Key/Secret Key and try again.', 'authforge-login-security')), 400);
        }

        wp_send_json_success(array('message' => __('Turnstile verification passed.', 'authforge-login-security')));
    }

    public function sanitize_checkbox($value) {
        return $value ? '1' : '0';
    }

    private function render_turnstile_test_modal() {
        ?>
        <div class="authforge-login-security-modal" id="authforge-login-security-turnstile-modal" hidden>
            <div class="authforge-login-security-modal__backdrop" data-close="1"></div>
            <div class="authforge-login-security-modal__card" role="dialog" aria-modal="true" aria-labelledby="authforge-login-security-turnstile-modal-title">
                <button type="button" class="authforge-login-security-modal__close" id="authforge-login-security-turnstile-close" aria-label="<?php esc_attr_e('Close', 'authforge-login-security'); ?>">&times;</button>
                <h3 id="authforge-login-security-turnstile-modal-title"><?php esc_html_e('Turnstile Live Test', 'authforge-login-security'); ?></h3>
                <p><?php esc_html_e('Complete the challenge below. The plugin will verify the token with the Secret Key you entered.', 'authforge-login-security'); ?></p>
                <div id="authforge-login-security-turnstile-widget"></div>
                <p id="authforge-login-security-turnstile-message" class="authforge-login-security-message"></p>
            </div>
        </div>
        <?php
    }

    private function get_settings_i18n_strings() {
        return array(
            'missingKeys' => __('Please enter both Turnstile Site Key and Secret Key.', 'authforge-login-security'),
            'loading' => __('Loading challenge...', 'authforge-login-security'),
            'verifying' => __('Verifying challenge...', 'authforge-login-security'),
            'success' => __('Turnstile test passed.', 'authforge-login-security'),
            'error' => __('Turnstile test failed. Please try again.', 'authforge-login-security'),
            'loadError' => __('Unable to load Turnstile script. Refresh and try again.', 'authforge-login-security'),
            'expired' => __('Challenge expired. Please complete it again.', 'authforge-login-security'),
        );
    }
}
