<?php
/**
 * Registers all public-facing shortcodes.
 *
 * @package    Simple_User_Access
 * @subpackage Simple_User_Access/public
 */
class SUA_Shortcodes {

    /**
     * The constructor registers all shortcodes with WordPress.
     */
    public function __construct() {
        add_shortcode('sua_google_button', [$this, 'google_button_view']);
        add_shortcode('sua_email_register_form', [$this, 'email_register_form_view']);
        add_shortcode('sua_email_login_form', [$this, 'email_login_form_view']);
        add_shortcode('sua_whatsapp_register_form', [$this, 'whatsapp_register_form_view']);
        add_shortcode('sua_whatsapp_login_form', [$this, 'whatsapp_login_form_view']);
        add_shortcode('sua_otp_verification_form', [$this, 'otp_verification_form_view']);
    }

    public function google_button_view($atts) {
        ob_start();
        require SUA_PLUGIN_DIR . 'includes/public/views/shortcode-google-button.php';
        return ob_get_clean();
    }

    public function email_register_form_view($atts) {
        ob_start();
        require SUA_PLUGIN_DIR . 'includes/public/views/shortcode-email-register-form.php';
        return ob_get_clean();
    }

    public function email_login_form_view($atts) {
        ob_start();
        require SUA_PLUGIN_DIR . 'includes/public/views/shortcode-email-login-form.php';
        return ob_get_clean();
    }

    public function whatsapp_register_form_view($atts) {
        ob_start();
        require SUA_PLUGIN_DIR . 'includes/public/views/shortcode-whatsapp-register-form.php';
        return ob_get_clean();
    }

    public function whatsapp_login_form_view($atts) {
        ob_start();
        require SUA_PLUGIN_DIR . 'includes/public/views/shortcode-whatsapp-login-form.php';
        return ob_get_clean();
    }

    public function otp_verification_form_view($atts) {
        if (!session_id()) { session_start(); }

        // REVISI: Periksa apakah salah satu dari sesi login ATAU sesi registrasi ada.
        if (empty($_SESSION['sua_verifying_user_id']) && empty($_SESSION['sua_verifying_reg_key'])) {
            return '<div class="sua-notice sua-notice-error">Sesi verifikasi tidak valid atau telah berakhir. Silakan ulangi proses login/pendaftaran.</div>';
        }
        
        ob_start();
        require SUA_PLUGIN_DIR . 'includes/public/views/shortcode-otp-verification-form.php';
        return ob_get_clean();
    }
}


