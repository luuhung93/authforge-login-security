<?php
namespace AuthForge\LoginSecurity;

if (!defined('ABSPATH')) {
    exit;
}

trait AuthForge_Login_Security_Profile_UI_Trait {
    public function enqueue_admin_assets($hook_suffix) {
        if ($hook_suffix !== 'profile.php' && $hook_suffix !== 'user-edit.php') {
            return;
        }

        $target_user_id = $this->get_profile_target_user_id();
        if (!$target_user_id || !current_user_can('edit_user', $target_user_id)) {
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
            'authforge-login-security-qrcode',
            $base_url . 'jquery.qrcode.min.js',
            array('jquery'),
            $this->get_asset_version($base_path . 'jquery.qrcode.min.js'),
            true
        );

        wp_enqueue_script(
            'authforge-login-security-admin',
            $base_url . 'admin.js',
            array('jquery', 'authforge-login-security-qrcode'),
            $this->get_asset_version($base_path . 'admin.js'),
            true
        );

        wp_localize_script('authforge-login-security-admin', 'AuthForgeLoginSecurity', array(
            'ajaxUrl' => admin_url('admin-ajax.php'),
            'userId' => $target_user_id,
            'nonce' => wp_create_nonce($this->get_manage_nonce_action($target_user_id)),
            'actions' => array(
                'startSetup' => AuthForge_Login_Security_Plugin::AJAX_ACTION_START_SETUP,
                'confirmSetup' => AuthForge_Login_Security_Plugin::AJAX_ACTION_CONFIRM_SETUP,
                'regenerateBackup' => AuthForge_Login_Security_Plugin::AJAX_ACTION_REGENERATE_BACKUP,
                'disableTwoFa' => AuthForge_Login_Security_Plugin::AJAX_ACTION_DISABLE_2FA,
            ),
            'i18n' => $this->get_admin_i18n_strings(),
        ));
    }

    public function render_profile_panel($user) {
        if (!($user instanceof \WP_User) || !current_user_can('edit_user', $user->ID)) {
            return;
        }

        $enabled = $this->is_enabled_for_user($user->ID);
        $remaining = $this->count_backup_codes($user->ID);
        ?>
        <h2><?php esc_html_e('AuthForge Login Security', 'authforge-login-security'); ?></h2>
        <table class="form-table" role="presentation">
            <?php $this->render_profile_status_row($enabled); ?>
            <?php $this->render_profile_backup_row($remaining); ?>
            <?php $this->render_profile_actions_row($enabled); ?>
        </table>

        <?php $this->render_setup_modal(); ?>
        <?php
    }

    private function render_profile_status_row($enabled) {
        ?>
        <tr>
            <th><?php esc_html_e('Status', 'authforge-login-security'); ?></th>
            <td>
                <strong id="authforge-login-security-status-text"><?php echo $enabled ? esc_html__('Enabled', 'authforge-login-security') : esc_html__('Disabled', 'authforge-login-security'); ?></strong>
                <p class="description"><?php esc_html_e('2FA is required at wp-login for this user when enabled.', 'authforge-login-security'); ?></p>
            </td>
        </tr>
        <?php
    }

    private function render_profile_backup_row($remaining) {
        ?>
        <tr>
            <th><?php esc_html_e('Backup codes', 'authforge-login-security'); ?></th>
            <td>
                <span id="authforge-login-security-backup-count"><?php echo esc_html((string) $remaining); ?></span>
                <span><?php esc_html_e('codes remaining', 'authforge-login-security'); ?></span>
            </td>
        </tr>
        <?php
    }

    private function render_profile_actions_row($enabled) {
        ?>
        <tr>
            <th><?php esc_html_e('Actions', 'authforge-login-security'); ?></th>
            <td>
                <button type="button" class="button button-primary" id="authforge-login-security-open-setup">
                    <?php echo $enabled ? esc_html__('Reconfigure 2FA', 'authforge-login-security') : esc_html__('Enable 2FA', 'authforge-login-security'); ?>
                </button>
                <button type="button" class="button" id="authforge-login-security-regen-backups" <?php disabled(!$enabled); ?>>
                    <?php esc_html_e('Regenerate backup codes', 'authforge-login-security'); ?>
                </button>
                <button type="button" class="button" id="authforge-login-security-disable" <?php disabled(!$enabled); ?>>
                    <?php esc_html_e('Disable 2FA', 'authforge-login-security'); ?>
                </button>
            </td>
        </tr>
        <?php
    }

    private function render_setup_modal() {
        ?>
        <div class="authforge-login-security-modal" id="authforge-login-security-modal" hidden>
            <div class="authforge-login-security-modal__backdrop" data-close="1"></div>
            <div class="authforge-login-security-modal__card" role="dialog" aria-modal="true" aria-labelledby="authforge-login-security-modal-title">
                <button type="button" class="authforge-login-security-modal__close" id="authforge-login-security-close" aria-label="Close">&times;</button>
                <h3 id="authforge-login-security-modal-title"><?php esc_html_e('Set up Two-Factor Authentication', 'authforge-login-security'); ?></h3>

                <div id="authforge-login-security-setup-step">
                    <p class="authforge-login-security-warning">
                        <?php esc_html_e('Warning: This setup replaces the previous secret. Old authenticator devices will no longer generate valid codes.', 'authforge-login-security'); ?>
                    </p>
                    <p><?php esc_html_e('1) Scan this QR code in your authenticator app.', 'authforge-login-security'); ?></p>
                    <div id="authforge-login-security-qr" aria-label="QR"></div>
                    <p><?php esc_html_e('2) If needed, enter this secret manually:', 'authforge-login-security'); ?></p>
                    <p><code id="authforge-login-security-secret"></code></p>
                    <p><?php esc_html_e('3) Enter the 6-digit code to verify setup.', 'authforge-login-security'); ?></p>
                    <input type="text" id="authforge-login-security-otp" class="regular-text" inputmode="numeric" maxlength="6" />
                    <p>
                        <button type="button" class="button button-primary" id="authforge-login-security-verify"><?php esc_html_e('Verify and Enable', 'authforge-login-security'); ?></button>
                    </p>
                </div>

                <div id="authforge-login-security-backup-step" hidden>
                    <p><strong><?php esc_html_e('Backup codes (show once)', 'authforge-login-security'); ?></strong></p>
                    <p><?php esc_html_e('Use each code once if you cannot access your authenticator app.', 'authforge-login-security'); ?></p>
                    <p>
                        <button type="button" class="button" id="authforge-login-security-copy-backups"><?php esc_html_e('Copy backup codes', 'authforge-login-security'); ?></button>
                    </p>
                    <ul id="authforge-login-security-backup-list"></ul>
                </div>

                <p id="authforge-login-security-message" class="authforge-login-security-message"></p>
            </div>
        </div>
        <?php
    }

    private function get_admin_i18n_strings() {
        return array(
            'loading' => __('Loading...', 'authforge-login-security'),
            'error' => __('Something went wrong. Please try again.', 'authforge-login-security'),
            'otpPlaceholder' => __('Enter 6-digit code', 'authforge-login-security'),
            'setupSuccess' => __('2FA is enabled. Save backup codes now.', 'authforge-login-security'),
            'regenSuccess' => __('New backup codes generated.', 'authforge-login-security'),
            'disableConfirm' => __('Disable 2FA for this account?', 'authforge-login-security'),
            'enabledText' => __('Enabled', 'authforge-login-security'),
            'disabledText' => __('Disabled', 'authforge-login-security'),
            'copySuccess' => __('Backup codes copied.', 'authforge-login-security'),
            'copyError' => __('Cannot copy automatically. Please copy manually.', 'authforge-login-security'),
        );
    }

    private function get_asset_version($path) {
        return (string) filemtime($path);
    }

    private function get_profile_target_user_id() {
        if (isset($_GET['user_id'])) {
            return absint(wp_unslash($_GET['user_id']));
        }

        $current_id = get_current_user_id();
        return $current_id > 0 ? $current_id : 0;
    }
}
