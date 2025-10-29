<?php
/**
 * File: class-sua-admin.php
 * Status: VERIFIED & FINAL
 * Revision Note:
 * - This file contains the definitive fix for the toggle reset bug.
 * - The `sanitize_settings()` function has been rewritten to use a hidden input field (`sua_current_page_slug`) to reliably detect the current settings page.
 * - The unreliable `_wp_http_referer` logic has been completely removed.
 * - The debugging `error_log` statements have been removed.
 * - `render_settings_page()` is updated to pass the page slug to the view file.
 * - No other functions in this file have been altered.
 *
 * @package    Simple_User_Access
 * @subpackage Simple_User_Access/admin
 */
class SUA_Admin {

    private $plugin_name;
    private $version;
    private $toggle_fields = [
        'simple-user-access' => ['record_user_ip'],
        'sua-email-settings' => ['email_enable_recaptcha', 'email_enable_nonce'],
        'sua-whatsapp-settings' => ['whatsapp_enable_recaptcha', 'whatsapp_enable_nonce']
    ];

    public function __construct($plugin_name, $version) {
        $this->plugin_name = $plugin_name;
        $this->version = $version;
    }

    public function enqueue_styles_and_scripts($hook_suffix) {
        
        // Daftar semua halaman admin yang digunakan oleh plugin ini
        $plugin_pages = [
            'users.php',                                    // Halaman daftar pengguna
            'toplevel_page_simple-user-access',             // Halaman Pengaturan Umum
            'user-access_page_sua-google-settings',         // Halaman Pengaturan Google
            'user-access_page_sua-email-settings',          // Halaman Pengaturan Email
            'user-access_page_sua-whatsapp-settings',       // Halaman Pengaturan WhatsApp
            'user-access_page_sua-activity-log'             // Halaman Log (dari Implementasi 2)
        ];

        // Hanya muat aset kita jika berada di salah satu halaman plugin
        if (in_array($hook_suffix, $plugin_pages)) {
            
            // Muat CSS Admin
            wp_enqueue_style($this->plugin_name, plugin_dir_url(__FILE__) . 'css/sua-admin.css', array(), $this->version, 'all');

            // Muat JS Admin
            wp_enqueue_script($this->plugin_name . '-user-script', plugin_dir_url(__FILE__) . 'js/sua-admin.js', ['jquery'], $this->version, true);

            // Lokalisisasi variabel untuk JS (termasuk nonce tes yang baru)
            wp_localize_script($this->plugin_name . '-user-script', 'sua_admin_vars', [
                'ajax_url'   => admin_url('admin-ajax.php'),
                'nonce'      => wp_create_nonce('sua_update_user_status_nonce'),
                'test_nonce' => wp_create_nonce('sua_api_test_nonce') // Nonce untuk tombol tes
            ]);
        }
    }
    
    public function create_admin_menu() {
        add_menu_page('Simple User Access', 'User Access', 'manage_options', $this->plugin_name, [$this, 'render_settings_page'], 'dashicons-admin-users', 81);
        add_submenu_page($this->plugin_name, 'Pengaturan Umum', 'Pengaturan Umum', 'manage_options', $this->plugin_name, [$this, 'render_settings_page']);
        add_submenu_page($this->plugin_name, 'Pengaturan Login Google', 'Daftar/Login Google', 'manage_options', 'sua-google-settings', [$this, 'render_settings_page']);
        add_submenu_page($this->plugin_name, 'Pengaturan Login Email', 'Daftar/Login Email', 'manage_options', 'sua-email-settings', [$this, 'render_settings_page']);
        add_submenu_page($this->plugin_name, 'Pengaturan Login WhatsApp', 'Daftar/Login WhatsApp', 'manage_options', 'sua-whatsapp-settings', [$this, 'render_settings_page']);
        add_submenu_page($this->plugin_name, 'Log Aktivitas', 'Log Aktivitas', 'manage_options', 'sua-activity-log', [$this, 'render_log_page']);
    }

    /**
     * REVISION: Pass the current page slug to the view file.
     */
    public function render_settings_page() {
        $current_page_slug = isset($_GET['page']) ? sanitize_key($_GET['page']) : $this->plugin_name;
        // The view file will use $current_page_slug.
        require_once plugin_dir_path(__FILE__) . 'views/settings-page.php';
    }

    public function register_settings() {
        require_once plugin_dir_path( __FILE__ ) . 'class-sua-settings-callbacks.php';
        register_setting('sua_settings_group', 'sua_settings', [$this, 'sanitize_settings']);
        $callbacks = new SUA_Settings_Callbacks();
        
        $general_page_slug = $this->plugin_name;
        $google_page_slug = 'sua-google-settings';
        $email_page_slug = 'sua-email-settings';
        $whatsapp_page_slug = 'sua-whatsapp-settings';

        add_settings_section('sua_general_section', 'Pengaturan Halaman & Redirect', null, $general_page_slug);
        add_settings_field('login_page', 'Halaman Login Kustom', [$callbacks, 'page_select_callback'], $general_page_slug, 'sua_general_section', ['name' => 'login_page']);
        add_settings_field('register_page', 'Halaman Register Kustom', [$callbacks, 'page_select_callback'], $general_page_slug, 'sua_general_section', ['name' => 'register_page']);
        add_settings_field('verification_page', 'Halaman Verifikasi OTP', [$callbacks, 'page_select_callback'], $general_page_slug, 'sua_general_section', ['name' => 'verification_page']);
        add_settings_field('redirect_logged_in', 'Redirect Pengguna Sudah Login', [$callbacks, 'page_select_callback'], $general_page_slug, 'sua_general_section', ['name' => 'redirect_logged_in']);
        add_settings_field('redirect_logout', 'Halaman Redirect Setelah Logout', [$callbacks, 'page_select_callback'], $general_page_slug, 'sua_general_section', ['name' => 'redirect_logout', 'description' => 'Jika kosong, akan dialihkan ke halaman login kustom.']);
        add_settings_field('redirect_subscriber', 'Redirect Role Subscriber', [$callbacks, 'page_select_callback'], $general_page_slug, 'sua_general_section', ['name' => 'redirect_subscriber']);
        add_settings_field('redirect_author', 'Redirect Role Author', [$callbacks, 'page_select_callback'], $general_page_slug, 'sua_general_section', ['name' => 'redirect_author']);
        add_settings_field('redirect_editor', 'Redirect Role Editor', [$callbacks, 'page_select_callback'], $general_page_slug, 'sua_general_section', ['name' => 'redirect_editor']);
        add_settings_field('redirect_administrator', 'Redirect Role Administrator', [$callbacks, 'page_select_callback'], $general_page_slug, 'sua_general_section', ['name' => 'redirect_administrator', 'description' => 'Jika kosong, akan dialihkan ke Dasbor Admin.']);

        add_settings_section('sua_welcome_email_section', 'Pengaturan Email Selamat Datang', null, $general_page_slug);
        add_settings_field('welcome_email_subject', 'Subjek Email', [$callbacks, 'text_callback'], $general_page_slug, 'sua_welcome_email_section', ['name' => 'welcome_email_subject']);
        add_settings_field('welcome_email_body', 'Isi Email', [$callbacks, 'wp_editor_callback'], $general_page_slug, 'sua_welcome_email_section', ['name' => 'welcome_email_body']);

        add_settings_section('sua_recaptcha_section', 'Pengaturan reCAPTCHA v3', null, $general_page_slug);
        add_settings_field('recaptcha_site_key', 'Site Key', [$callbacks, 'password_callback'], $general_page_slug, 'sua_recaptcha_section', ['name' => 'recaptcha_site_key']);
        add_settings_field('recaptcha_secret_key', 'Secret Key', [$callbacks, 'password_callback'], $general_page_slug, 'sua_recaptcha_section', ['name' => 'recaptcha_secret_key']);
        add_settings_field('recaptcha_threshold', 'Score Threshold', [$callbacks, 'text_callback'], $general_page_slug, 'sua_recaptcha_section', ['name' => 'recaptcha_threshold', 'type' => 'number', 'step' => '0.1', 'min' => '0.0', 'max' => '1.0']);
        add_settings_field('recaptcha_test_button', 'Uji reCAPTCHA', [$callbacks, 'recaptcha_test_button_callback'], $general_page_slug, 'sua_recaptcha_section');
        
        add_settings_section('sua_rate_limit_section', 'Pengaturan Rate Limit (Pembatasan)', null, $general_page_slug);
        add_settings_field('record_user_ip', 'Catat IP Pengguna', [$callbacks, 'toggle_switch_callback'], $general_page_slug, 'sua_rate_limit_section', ['name' => 'record_user_ip']);
        add_settings_field('rate_limit_register_ip', 'Batas Pendaftaran (per Jam per IP)', [$callbacks, 'text_callback'], $general_page_slug, 'sua_rate_limit_section', ['name' => 'rate_limit_register_ip', 'type' => 'number', 'description' => 'Default: 10. Jumlah pendaftaran maks. dari 1 IP per jam. Isi 0 untuk menonaktifkan.']);
        add_settings_field('rate_limit_login_email', 'Batas Login Dengan Email', [$callbacks, 'text_callback'], $general_page_slug, 'sua_rate_limit_section', ['name' => 'rate_limit_login_email', 'type' => 'number', 'description' => 'Default: 3. Jumlah permintaan login maks. per email. Isi 0 untuk menonaktifkan.']);
        add_settings_field('rate_limit_login_whatsapp', 'Batas Login Dengan No WA', [$callbacks, 'text_callback'], $general_page_slug, 'sua_rate_limit_section', ['name' => 'rate_limit_login_whatsapp', 'type' => 'number', 'description' => 'Default: 3. Jumlah permintaan login maks. per No. WA. Isi 0 untuk menonaktifkan.']);
        add_settings_field('rate_limit_login_ip', 'Batas Login Per IP', [$callbacks, 'text_callback'], $general_page_slug, 'sua_rate_limit_section', ['name' => 'rate_limit_login_ip', 'type' => 'number', 'description' => 'Default: 6. Jumlah permintaan login maks. dari 1 IP (global). Isi 0 untuk menonaktifkan.']);
        add_settings_field('rate_limit_login_period', 'Waktu Pembatasan Login (menit)', [$callbacks, 'text_callback'], $general_page_slug, 'sua_rate_limit_section', ['name' => 'rate_limit_login_period', 'type' => 'number', 'description' => 'Default: 10. Durasi pembatasan login dalam menit.']);
        add_settings_field('rate_limit_otp_attempts', 'Batas Percobaan Verifikasi Salah', [$callbacks, 'text_callback'], $general_page_slug, 'sua_rate_limit_section', ['name' => 'rate_limit_otp_attempts', 'type' => 'number', 'description' => 'Default: 3. Jumlah percobaan salah maks. sebelum sesi dibatalkan. Isi 0 untuk menonaktifkan.']);

        add_settings_section('sua_otp_section', 'Pengaturan OTP', null, $general_page_slug);
        add_settings_field('otp_digits', 'Jumlah Digit OTP', [$callbacks, 'text_callback'], $general_page_slug, 'sua_otp_section', ['name' => 'otp_digits', 'type' => 'number']);
        add_settings_field('otp_validity', 'Masa Berlaku OTP (detik)', [$callbacks, 'text_callback'], $general_page_slug, 'sua_otp_section', ['name' => 'otp_validity', 'type' => 'number']);
        add_settings_field('otp_resend_wait', 'Waktu Tunggu Kirim Ulang OTP (detik)', [$callbacks, 'text_callback'], $general_page_slug, 'sua_otp_section', ['name' => 'otp_resend_wait', 'type' => 'number']);
        add_settings_field('otp_rate_limit', 'Batas Permintaan OTP', [$callbacks, 'text_callback'], $general_page_slug, 'sua_otp_section', ['name' => 'otp_rate_limit', 'type' => 'number']);
        add_settings_field('otp_rate_limit_reset', 'Waktu Reset Batas Permintaan (menit)', [$callbacks, 'text_callback'], $general_page_slug, 'sua_otp_section', ['name' => 'otp_rate_limit_reset', 'type' => 'number']);

        add_settings_section('sua_google_section', 'Pengaturan API Google', null, $google_page_slug);
        add_settings_field('google_client_id', 'Google Client ID', [$callbacks, 'password_callback'], $google_page_slug, 'sua_google_section', ['name' => 'google_client_id']);
        add_settings_field('google_client_secret', 'Google Client Secret', [$callbacks, 'password_callback'], $google_page_slug, 'sua_google_section', ['name' => 'google_client_secret']);
        add_settings_field('google_callback_url', 'Authorized Redirect URI', [$callbacks, 'display_readonly_text_callback'], $google_page_slug, 'sua_google_section', ['value' => home_url('/?sua-action=google_callback'), 'description' => 'Salin URL ini dan tempelkan di kolom "Authorized redirect URIs" pada Google Cloud Console Anda.']);
        add_settings_field('google_login_shortcode', 'Shortcode Tombol Google', [$callbacks, 'shortcode_display_callback'], $google_page_slug, 'sua_google_section', ['shortcode' => '[sua_google_button]']);

        add_settings_section('sua_email_section', 'Pengaturan Keamanan Form Email', null, $email_page_slug);
        add_settings_field('email_whitelist', 'Whitelist Domain Email', [$callbacks, 'textarea_callback'], $email_page_slug, 'sua_email_section', ['name' => 'email_whitelist', 'description' => 'Masukkan satu atau beberapa domain, pisahkan dengan koma (contoh: gmail.com, yahoo.com). Jika diisi, hanya domain ini yang diizinkan.']);
        add_settings_field('email_blacklist', 'Blacklist Domain Email', [$callbacks, 'textarea_callback'], $email_page_slug, 'sua_email_section', ['name' => 'email_blacklist', 'description' => 'Masukkan satu atau beberapa domain, pisahkan dengan koma. Aturan ini hanya berlaku jika Whitelist kosong.']);
        add_settings_field('email_enable_recaptcha', 'Aktifkan reCAPTCHA', [$callbacks, 'toggle_switch_callback'], $email_page_slug, 'sua_email_section', ['name' => 'email_enable_recaptcha']);
        add_settings_field('email_enable_nonce', 'Aktifkan Nonce (CSRF Protection)', [$callbacks, 'toggle_switch_callback'], $email_page_slug, 'sua_email_section', ['name' => 'email_enable_nonce']);
        
        add_settings_section('sua_email_otp_template_section', 'Template Email OTP', null, $email_page_slug);
        add_settings_field('otp_email_subject', 'Subjek Email OTP', [$callbacks, 'text_callback'], $email_page_slug, 'sua_email_otp_template_section', ['name' => 'otp_email_subject']);
        add_settings_field('otp_email_body', 'Isi Email OTP', [$callbacks, 'wp_editor_callback'], $email_page_slug, 'sua_email_otp_template_section', ['name' => 'otp_email_body']);
        
        add_settings_section('sua_email_shortcodes_section', 'Shortcode Form Email', null, $email_page_slug);
        add_settings_field('email_register_shortcode', 'Form Daftar', [$callbacks, 'shortcode_display_callback'], $email_page_slug, 'sua_email_shortcodes_section', ['shortcode' => '[sua_email_register_form]']);
        add_settings_field('email_login_shortcode', 'Form Login', [$callbacks, 'shortcode_display_callback'], $email_page_slug, 'sua_email_shortcodes_section', ['shortcode' => '[sua_email_login_form]']);

        add_settings_section('sua_whatsapp_security_section', 'Pengaturan Keamanan Form WhatsApp', null, $whatsapp_page_slug);
        add_settings_field('whatsapp_enable_recaptcha', 'Aktifkan reCAPTCHA', [$callbacks, 'toggle_switch_callback'], $whatsapp_page_slug, 'sua_whatsapp_security_section', ['name' => 'whatsapp_enable_recaptcha']);
        add_settings_field('whatsapp_enable_nonce', 'Aktifkan Nonce (CSRF Protection)', [$callbacks, 'toggle_switch_callback'], $whatsapp_page_slug, 'sua_whatsapp_security_section', ['name' => 'whatsapp_enable_nonce']);
        
        add_settings_section('sua_whatsapp_api_section', 'Pengaturan Integrasi WAHA', null, $whatsapp_page_slug);
        add_settings_field('waha_api_endpoint', 'WAHA API Endpoint', [$callbacks, 'text_callback'], $whatsapp_page_slug, 'sua_whatsapp_api_section', ['name' => 'waha_api_endpoint', 'description' => 'Masukkan URL dasar dari server WAHA Anda (contoh: http://localhost:3000)']);
        add_settings_field('waha_session_name', 'WAHA Session Name', [$callbacks, 'text_callback'], $whatsapp_page_slug, 'sua_whatsapp_api_section', ['name' => 'waha_session_name']);
        add_settings_field('whatsapp_default_country_code', 'Kode Negara Default', [$callbacks, 'text_callback'], $whatsapp_page_slug, 'sua_whatsapp_api_section', ['name' => 'whatsapp_default_country_code', 'description' => 'Contoh: 62 untuk Indonesia. Kosongkan jika tidak diperlukan.']);
        add_settings_field('waha_api_key', 'WAHA API Key (Opsional)', [$callbacks, 'password_callback'], $whatsapp_page_slug, 'sua_whatsapp_api_section', ['name' => 'waha_api_key']);
        add_settings_field('waha_message_template', 'Template Pesan WhatsApp', [$callbacks, 'textarea_callback'], $whatsapp_page_slug, 'sua_whatsapp_api_section', ['name' => 'waha_message_template', 'description' => 'Placeholder yang tersedia: <code>{display_name}</code>, <code>{otp_code}</code>']);
        add_settings_field('waha_test_button', 'Uji WAHA', [$callbacks, 'waha_test_button_callback'], $whatsapp_page_slug, 'sua_whatsapp_api_section');
        
        add_settings_section('sua_whatsapp_shortcodes_section', 'Shortcode Form WhatsApp', null, $whatsapp_page_slug);
        add_settings_field('whatsapp_register_shortcode', 'Form Daftar', [$callbacks, 'shortcode_display_callback'], $whatsapp_page_slug, 'sua_whatsapp_shortcodes_section', ['shortcode' => '[sua_whatsapp_register_form]']);
        add_settings_field('whatsapp_login_shortcode', 'Form Login', [$callbacks, 'shortcode_display_callback'], $whatsapp_page_slug, 'sua_whatsapp_shortcodes_section', ['shortcode' => '[sua_whatsapp_login_form]']);
    }

    /**
     * REVISION: Rewritten with a foolproof method to preserve settings across pages.
     */
    public function sanitize_settings($input) {
        $options = get_option('sua_settings', []);
    
        // Sanitize the submitted data into a temporary array.
        $sanitized_input = [];
        if (!empty($input)) {
            foreach ($input as $key => $value) {
                if (strpos($key, 'body') !== false || strpos($key, 'template') !== false) {
                    $sanitized_input[$key] = wp_kses_post($value);
                } else {
                    $sanitized_input[$key] = sanitize_text_field($value);
                }
            }
        }
    
        // Reliably get the current page slug from the hidden input.
        $current_page_slug = isset($_POST['sua_current_page_slug']) ? sanitize_key($_POST['sua_current_page_slug']) : '';
    
        // Handle unchecked toggles specifically for the current page.
        if (!empty($current_page_slug) && isset($this->toggle_fields[$current_page_slug])) {
            foreach ($this->toggle_fields[$current_page_slug] as $field_name) {
                if (!isset($sanitized_input[$field_name])) {
                    $sanitized_input[$field_name] = '0';
                }
            }
        }
    
        // Merge the sanitized input over the old options.
        $final_options = array_merge($options, $sanitized_input);
    
        add_settings_error('sua_settings', 'sua_settings_updated', 'Pengaturan berhasil disimpan.', 'updated');
        
        return $final_options;
    }

    public function add_custom_user_columns($columns) {
        $columns['no_whatsapp'] = 'No WhatsApp';
        $columns['membership_status'] = 'Membership';
        $columns['ekyc_status'] = 'e-KYC Status';
        $options = get_option('sua_settings');
        if (!empty($options['record_user_ip'])) {
            $columns['ip_address'] = 'IP Address';
        }
        return $columns;
    }

    public function render_custom_user_columns($value, $column_name, $user_id) {
        switch ($column_name) {
            case 'membership_status':
                $status = get_user_meta($user_id, 'membership_status', true) ?: 'active';
                $checked = ($status === 'active') ? 'checked' : '';
                return "<label class='sua-switch'><input type='checkbox' class='sua-status-toggle' value='{$status}' data-user-id='{$user_id}' data-meta-key='membership_status' data-on-value='active' data-off-value='banned' {$checked}><span class='sua-slider sua-round'></span></label>";
            case 'ekyc_status':
                $status = get_user_meta($user_id, 'ekyc_status', true) ?: 'unverified';
                $checked = ($status === 'verified') ? 'checked' : '';
                return "<label class='sua-switch'><input type='checkbox' class='sua-status-toggle' value='{$status}' data-user-id='{$user_id}' data-meta-key='ekyc_status' data-on-value='verified' data-off-value='unverified' {$checked}><span class='sua-slider sua-round'></span></label>";
            case 'ip_address':
                return esc_html(get_user_meta($user_id, 'ip_address', true));
            case 'no_whatsapp':
                return esc_html(get_user_meta($user_id, 'no_whatsapp', true));
        }
        return $value;
    }

    public function add_sortable_user_columns($columns) {
        $columns['no_whatsapp'] = 'no_whatsapp';
        $columns['membership_status'] = 'membership_status';
        $columns['ekyc_status'] = 'ekyc_status';
        return $columns;
    }

    public function handle_user_status_update() {
    // 1️⃣ Cek nonce keamanan
    if ( ! check_ajax_referer('sua_update_user_status_nonce', 'nonce', false) ) {
        wp_send_json_error(['message' => 'Pemeriksaan keamanan gagal.'], 403);
    }

    // 2️⃣ Validasi izin admin/editor
    if ( ! current_user_can('edit_users') ) {
        wp_send_json_error(['message' => 'Anda tidak memiliki izin.']);
    }

    // 3️⃣ Ambil data input
    $user_id    = isset($_POST['user_id']) ? intval($_POST['user_id']) : 0;
    $meta_key   = isset($_POST['meta_key']) ? sanitize_key($_POST['meta_key']) : '';
    $new_status = isset($_POST['status']) ? sanitize_text_field($_POST['status']) : '';

    // 4️⃣ Validasi dan proses
    if ( $user_id > 0 && in_array($meta_key, ['membership_status', 'ekyc_status'], true) ) {

        // Update status user
        update_user_meta($user_id, $meta_key, $new_status);
        clean_user_cache($user_id);

        // 5️⃣ Jika status membership dibanned → hapus semua sesi aktif
        if ($meta_key === 'membership_status' && $new_status === 'banned') {
            if (class_exists('WP_Session_Tokens')) {
                $sessions = WP_Session_Tokens::get_instance($user_id);
                $sessions->destroy_all();
            }

            // Opsional: kirim notifikasi email
            $user = get_user_by('ID', $user_id);
            if ($user && !empty($user->user_email)) {
                wp_mail(
                    $user->user_email,
                    __('Akun Anda Telah Diblokir', 'simple-user-access'),
                    __('Akun Anda telah diblokir oleh administrator. Silakan hubungi dukungan jika ini kesalahan.', 'simple-user-access')
                );
            }
        }

        wp_send_json_success(['message' => 'Status pengguna berhasil diperbarui.']);
    } else {
        wp_send_json_error(['message' => 'Data tidak valid.']);
    }
}

/**
 * Menangani panggilan AJAX untuk menguji koneksi WAHA.
 */
public function handle_test_waha() {
    if (!check_ajax_referer('sua_api_test_nonce', 'nonce', false)) {
        wp_send_json_error(['message' => 'Pemeriksaan keamanan gagal.'], 403);
    }
    if (!current_user_can('manage_options')) {
        wp_send_json_error(['message' => 'Anda tidak memiliki izin.'], 403);
    }

    $test_number = sanitize_text_field($_POST['test_number'] ?? '');
    if (empty($test_number)) {
        wp_send_json_error(['message' => 'Nomor tes WA tidak boleh kosong.']);
    }

    $message = "Ini adalah pesan tes dari " . get_bloginfo('name') . ". Jika Anda menerima ini, pengaturan WAHA Anda sudah benar.";

    // Gunakan helper yang ada, tapi panggil langsung
    $sent = SUA_Helpers::send_otp_whatsapp_direct($test_number, 'Admin Test', $message);

    if ($sent) {
        wp_send_json_success(['message' => 'Pesan tes berhasil dikirim ke ' . $test_number]);
    } else {
        // Ambil notice error yang mungkin diset oleh helper
        $notices = get_transient('sua_notices');
        delete_transient('sua_notices');
        $error_message = $notices[0]['message'] ?? 'Gagal mengirim pesan. Periksa log error.';
        wp_send_json_error(['message' => $error_message]);
    }
}

/**
 * Menangani panggilan AJAX untuk menguji reCAPTCHA Secret.
 */
public function handle_test_recaptcha() {
    if (!check_ajax_referer('sua_api_test_nonce', 'nonce', false)) {
        wp_send_json_error(['message' => 'Pemeriksaan keamanan gagal.'], 403);
    }
    if (!current_user_can('manage_options')) {
        wp_send_json_error(['message' => 'Anda tidak memiliki izin.'], 403);
    }

    // Panggil helper baru (yang akan kita buat di Langkah 5)
    $result = SUA_Helpers::test_recaptcha_secret();

    if ($result['success']) {
        wp_send_json_success(['message' => $result['message']]);
    } else {
        wp_send_json_error(['message' => $result['message']]);
    }
}

/**
 * Merender halaman admin untuk menampilkan log aktivitas.
 */
public function render_log_page() {
    global $wpdb;
    $table_name = $wpdb->prefix . 'sua_logs';

    // Ambil 100 log terbaru
    $logs = $wpdb->get_results(
        $wpdb->prepare("SELECT * FROM $table_name ORDER BY timestamp DESC LIMIT %d", 100)
    );
    ?>
    <div class="wrap">
        <h1>Log Aktivitas Simple User Access (100 Terbaru)</h1>
        <p>Menampilkan kejadian login, registrasi, dan upaya yang gagal.</p>

        <table class="wp-list-table widefat fixed striped">
            <thead>
                <tr>
                    <th style="width: 160px;">Waktu</th>
                    <th style="width: 120px;">Tipe Kejadian</th>
                    <th>Pesan</th>
                    <th style="width: 100px;">User ID</th>
                    <th style="width: 120px;">Alamat IP</th>
                </tr>
            </thead>
            <tbody>
                <?php if (empty($logs)) : ?>
                    <tr>
                        <td colspan="5">Belum ada log yang tercatat.</td>
                    </tr>
                <?php else : ?>
                    <?php foreach ($logs as $log) : ?>
                        <tr>
                            <td><?php echo esc_html($log->timestamp); ?></td>
                            <td><strong><?php echo esc_html($log->event_type); ?></strong></td>
                            <td><?php echo esc_html($log->message); ?></td>
                            <td><?php echo $log->user_id ? esc_html($log->user_id) : 'N/A'; ?></td>
                            <td><?php echo esc_html($log->ip_address); ?></td>
                        </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
            </tbody>
        </table>
    </div>
    <?php
}

}
