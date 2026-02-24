=== AuthForge Login Security ===
Contributors: luuhung93
Tags: 2fa, two-factor authentication, login security, otp, totp, turnstile
Requires at least: 6.0
Tested up to: 6.9
Requires PHP: 7.4
Stable tag: 1.3.2
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Lightweight two-factor authentication for WordPress login with optional Cloudflare Turnstile.

== Description ==

AuthForge Login Security adds TOTP-based 2FA to WordPress login with a clean two-step flow.

Features:
- Two-step login flow
- Step 1: username/password (+ optional Turnstile)
- Step 2: OTP or backup code (only when user has 2FA enabled)
- Profile modal setup with QR code and manual secret
- OTP verification before activation
- 9 backup codes per generation
- Regenerate backup codes (old codes are invalid immediately)
- Copy backup codes button
- Turnstile settings page with live verification popup
- Reconfigure warning when replacing existing secret

== Installation ==

1. Upload the plugin folder to `/wp-content/plugins/authforge-login-security/`.
2. Activate the plugin through the Plugins menu in WordPress.
3. (Optional) Configure Turnstile in Settings -> AuthForge Login Security.
4. Go to Users -> Profile and click Enable 2FA.
5. Scan QR code, verify OTP, and store backup codes safely.

== Frequently Asked Questions ==

= If a user has not enabled 2FA, do they need OTP? =

No. They login normally with username and password (plus Turnstile if enabled).

= What happens when I regenerate backup codes? =

A new set is created and all old backup codes are invalid immediately.

= What happens when I reconfigure 2FA? =

A new secret is generated. Old authenticator entries/devices will stop working.

== External services ==

This plugin can integrate with Cloudflare Turnstile to add an anti-bot challenge on login.

Service: Cloudflare Turnstile (`challenges.cloudflare.com`)
- Used for: rendering the challenge widget and verifying challenge tokens.
- Data sent: Turnstile response token and visitor IP address.
- When sent: during wp-login authentication when Turnstile is enabled, and during admin Turnstile test in plugin settings.
- Endpoints used:
  - `https://challenges.cloudflare.com/turnstile/v0/api.js`
  - `https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit`
  - `https://challenges.cloudflare.com/turnstile/v0/siteverify`
- Terms of Service: `https://www.cloudflare.com/website-terms/`
- Privacy Policy: `https://www.cloudflare.com/privacypolicy/`

== Screenshots ==

1. 2FA setup popup with QR and verification (`screenshot-1.png`).
2. Login form with Turnstile enabled (`screenshot-2.png`).

== Changelog ==

= 1.3.2 =
* Added PHP namespace `AuthForge\\LoginSecurity` across plugin classes/traits.
* Reduced repeated technical strings by centralizing core action/nonce/settings constants.
* Added nonce verification for the login OTP step.
* Added explicit `load_plugin_textdomain()` on `plugins_loaded`.

= 1.3.1 =
* Switched internal technical prefixes from `simple_*` to `authforge_*`.
* Updated plugin name/slug references to AuthForge Login Security.
* Added external services documentation for Cloudflare Turnstile.

= 1.3.0 =
* Switched login to two-step flow: OTP screen is shown only for users with 2FA enabled.
* Added Turnstile live test popup on Settings page.
* Improved wp-login layout compatibility when Turnstile is enabled.
* Updated documentation and screenshots.

= 1.2.0 =
* Renamed plugin to AuthForge Login Security.
* Added optional Cloudflare Turnstile on login.
* Refactored plugin into class and trait files.

= 1.1.0 =
* Added setup modal with QR flow.
* Added one-time backup codes and regenerate action.
* Added copy backup codes button.

= 1.0.0 =
* Initial release.
