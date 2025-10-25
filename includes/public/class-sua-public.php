<?php
/**
 * File: class-sua-public.php
 * Status: VERIFIED & REVISED
 * Revision Note:
 * - This file fixes the critical bug that broke the "Resend OTP" AJAX functionality.
 * - The AJAX action hooks (`wp_ajax_sua_resend_otp` and `wp_ajax_nopriv_sua_resend_otp`) have been moved outside the conditional check in `init_authentication_handler`.
 * - This ensures that the AJAX endpoints are always registered with WordPress, allowing the server to correctly handle the "Resend OTP" request.
 * - No other functionality in this file has been altered.
 *
 * @package    Simple_User_Access
 * @subpackage Simple_User_Access/public
 */
class SUA_Public {

    private $plugin_name;
    private $version;

    public function __construct($plugin_name, $version) {
        $this->plugin_name = $plugin_name;
        $this->version = $version;
    }
    
    /**
     * Start the session reliably.
     */
    public function start_session() {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
    }

    /**
     * Enqueue styles and scripts for the public-facing side of the site.
     */
    public function enqueue_styles_and_scripts() {
        wp_enqueue_style($this->plugin_name, plugin_dir_url(__FILE__) . 'css/sua-public.css', array(), $this->version, 'all');

        // REVISI: Tentukan dependensi dasar
        $dependencies = ['jquery'];
        
        $site_key = SUA_Helpers::get_setting('recaptcha_site_key');

        // REVISI: Muat script Google reCAPTCHA *sebelum* script plugin Anda, jika ada site key
        if (!empty($site_key)) {
            wp_enqueue_script('google-recaptcha', "https://www.google.com/recaptcha/api.js?render={$site_key}", [], null, true);
            // REVISI: Tambahkan 'google-recaptcha' sebagai dependensi
            $dependencies[] = 'google-recaptcha';
        }

        // REVISI: Muat script plugin Anda (sua-public.js) *setelahnya*, dengan dependensi yang benar
        wp_enqueue_script($this->plugin_name, plugin_dir_url(__FILE__) . 'js/sua-public.js', $dependencies, $this->version, true);
        
        // Lokalisisasi variabel tetap sama
        wp_localize_script($this->plugin_name, 'sua_public_vars', [
            'ajax_url' => admin_url('admin-ajax.php'),
            'resend_otp_nonce' => wp_create_nonce('sua_resend_otp_nonce'),
            'recaptcha_site_key' => $site_key,
        ]);
    }
    
    /**
     * Register all shortcodes for the plugin.
     */
    public function register_shortcodes() {
        require_once plugin_dir_path(__FILE__) . 'class-sua-shortcodes.php';
        new SUA_Shortcodes();
    }
    
    /**
     * Initialize the authentication handler to process form submissions and API callbacks.
     */
    public function init_authentication_handler() {
        require_once plugin_dir_path(__FILE__) . 'class-sua-auth-handler.php';
        $auth_handler = new SUA_Auth_Handler();

        // FIX: AJAX hooks MUST be registered on every page load for WordPress to recognize them.
        // They are now moved outside of the conditional check.
        add_action('wp_ajax_sua_resend_otp', [$auth_handler, 'handle_ajax_resend_otp']);
        add_action('wp_ajax_nopriv_sua_resend_otp', [$auth_handler, 'handle_ajax_resend_otp']);

        // Only process standard form submissions if one of our actions is present.
        if (!isset($_POST['sua_action']) && !isset($_GET['sua-action'])) {
            return;
        }

        // The session is only started when processing a form submission.
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        if (isset($_POST['sua_action'])) {
            $action = sanitize_key($_POST['sua_action']);
            $method_name = 'handle_' . $action;
            if (method_exists($auth_handler, $method_name)) {
                call_user_func([$auth_handler, $method_name]);
            }
        }
        
        if (isset($_GET['sua-action'])) {
            $action = sanitize_key($_GET['sua-action']);
            $method_name = 'handle_' . $action;
            if (method_exists($auth_handler, $method_name)) {
                call_user_func([$auth_handler, $method_name]);
            }
        }
    }

    /**
     * Blocks direct access to wp-login.php.
     */
    public function block_wp_login_page() {
        global $pagenow;
        $custom_login_url = SUA_Helpers::get_login_page_url();

        if ( empty($custom_login_url) || $custom_login_url === home_url('/') ) {
            return;
        }

        $allowed_actions = ['logout', 'postpass'];
        $action = isset($_GET['action']) ? $_GET['action'] : '';

        if ( 
            $pagenow === 'wp-login.php' &&
            !is_admin() &&
            !defined('DOING_AJAX') &&
            !in_array($action, $allowed_actions, true) &&
            !isset($_POST['log'])
        ) {
            wp_safe_redirect($custom_login_url);
            exit();
        }
    }

    /**
     * Redirects logged-in users away from our custom auth pages.
     */
    public function redirect_logged_in_user_from_auth_pages() {
        if ( ! is_user_logged_in() || is_admin() ) {
            return;
        }

        $login_page_id = SUA_Helpers::get_setting('login_page');
        $register_page_id = SUA_Helpers::get_setting('register_page');
        $verification_page_id = SUA_Helpers::get_setting('verification_page');
        
        $auth_page_ids = array_filter([$login_page_id, $register_page_id, $verification_page_id]);

        if ( ! empty($auth_page_ids) && is_page($auth_page_ids) ) {
            $redirect_page_id = SUA_Helpers::get_setting('redirect_logged_in');
            $redirect_url = $redirect_page_id ? get_permalink($redirect_page_id) : home_url('/');
            
            wp_safe_redirect($redirect_url);
            exit();
        }
    }

    /**
     * Redirects user to the custom page after logout.
     */
    public function redirect_after_logout() {
        $logout_redirect_page_id = SUA_Helpers::get_setting('redirect_logout');
        
        if ($logout_redirect_page_id) {
            $redirect_url = get_permalink($logout_redirect_page_id);
        } else {
            $redirect_url = SUA_Helpers::get_login_page_url();
        }
        
        wp_safe_redirect($redirect_url);
        exit();
    }
}


