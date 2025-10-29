<?php
/**
 * File: class-sua-auth-handler.php
 * Status: REVISED WITH LOGGER
 * Revision Note:
 * - Integrated SUA_Logger::log() calls into all authentication workflows.
 * - Restored manual session_start() in handle_ajax_resend_otp to ensure 
 * it works with the 'smart' global session handler.
 *
 * @package    Simple_User_Access
 * @subpackage Simple_User_Access/public
 */
class SUA_Auth_Handler {

    public function __construct() {
        // Session start is correctly handled by the 'init' hook (global smart function)
    }

    private function validate_form_submission($form_type, $action_type) {
        // Persiapan logging untuk kegagalan
        $ip = SUA_Helpers::get_user_ip();
        $log_event_prefix = strtoupper($form_type) . '_' . strtoupper($action_type);

        if (SUA_Helpers::get_setting("{$form_type}_enable_nonce")) {
            $nonce = $_POST["sua_{$form_type}_{$action_type}_nonce"] ?? '';
            $action = "sua_{$form_type}_{$action_type}_action";
            if (!wp_verify_nonce($nonce, $action)) {
                SUA_Logger::log($log_event_prefix . '_NONCE_FAILED', 'Pemeriksaan Nonce gagal.', null, $ip);
                SUA_Helpers::add_notice('Sesi tidak valid atau telah kedaluwarsa. Silakan muat ulang halaman dan coba lagi.');
                return false;
            }
        }

        if (SUA_Helpers::get_setting("{$form_type}_enable_recaptcha")) {
            $token = $_POST['recaptcha_token'] ?? '';
            if (empty($token)) {
                SUA_Logger::log($log_event_prefix . '_RECAPTCHA_FAILED', 'Token reCAPTCHA kosong.', null, $ip);
                SUA_Helpers::add_notice('Token reCAPTCHA tidak ditemukan. Silakan coba lagi.');
                return false;
            }
            if (!SUA_Helpers::verify_recaptcha($token)) {
                SUA_Logger::log($log_event_prefix . '_RECAPTCHA_FAILED', 'Verifikasi reCAPTCHA gagal (skor rendah atau token tidak valid).', null, $ip);
                SUA_Helpers::add_notice('Verifikasi reCAPTCHA gagal. Anda mungkin terdeteksi sebagai bot.');
                return false;
            }
        }

        $required_fields = [];
        if ($action_type === 'register') {
            $required_fields = ['sua_first_name', 'sua_last_name'];
            if (!isset($_POST['sua_tos']) || $_POST['sua_tos'] !== 'on') {
                SUA_Logger::log($log_event_prefix . '_TOS_FAILED', 'Syarat & Ketentuan tidak dicentang.', null, $ip);
                SUA_Helpers::add_notice('Anda harus menerima Syarat & Ketentuan untuk mendaftar.');
                return false;
            }
        }
        $field_key = $form_type === 'whatsapp' ? 'sua_whatsapp' : 'sua_email';
        $required_fields[] = $field_key;

        foreach ($required_fields as $field) {
            if (empty($_POST[$field])) {
                SUA_Logger::log($log_event_prefix . '_EMPTY_FIELD', 'Kolom wajib tidak diisi: ' . $field, null, $ip);
                SUA_Helpers::add_notice('Semua kolom wajib diisi.');
                return false;
            }
        }
        
        return true;
    }


    public function handle_google_login() {
        $client_id = SUA_Helpers::get_setting('google_client_id');
        $redirect_uri = home_url('/?sua-action=google_callback');

        if(empty($client_id)) {
            // Catatan: Ini adalah error konfigurasi sisi server, IP tidak relevan.
            SUA_Logger::log('GOOGLE_CONFIG_ERROR', 'Google Client ID tidak diatur di admin.');
            SUA_Helpers::add_notice('Ada kesalahan, silahkan coba lagi.');
            wp_redirect(SUA_Helpers::get_login_page_url());
            exit;
        }

        $state = wp_generate_password(32, false);
        $_SESSION['sua_google_oauth_state'] = $state;

        $auth_url = 'https://accounts.google.com/o/oauth2/v2/auth?' . http_build_query([
        'client_id' => $client_id,
        'redirect_uri' => $redirect_uri,
        'response_type' => 'code',
        'scope' => 'openid email profile',
        'prompt' => 'select_account',
        'state' => $state
        ]);

        wp_redirect($auth_url);
        exit;
    }
    
    public function handle_google_callback() {
        $ip = SUA_Helpers::get_user_ip();

        // Verifikasi state
        if (!isset($_GET['state']) || !isset($_SESSION['sua_google_oauth_state']) || $_GET['state'] !== $_SESSION['sua_google_oauth_state']) {
            SUA_Logger::log('GOOGLE_LOGIN_FAILED', 'State OAuth tidak valid atau sesi kedaluwarsa.', null, $ip);
            SUA_Helpers::add_notice('Permintaan tidak valid atau sesi telah kedaluwarsa. Silakan coba lagi.');
            wp_redirect(SUA_Helpers::get_login_page_url());
            exit;
        }

        // Hapus state setelah digunakan
        unset($_SESSION['sua_google_oauth_state']);

        if (!isset($_GET['code'])) {
            SUA_Logger::log('GOOGLE_LOGIN_FAILED', 'Gagal menerima kode otorisasi dari Google.', null, $ip);
            SUA_Helpers::add_notice('Gagal menerima kode otorisasi dari Google.');
            wp_redirect(SUA_Helpers::get_login_page_url());
            exit;
        }

        $code = sanitize_text_field($_GET['code']);
        $client_id = SUA_Helpers::get_setting('google_client_id');
        $client_secret = SUA_Helpers::get_setting('google_client_secret');
        $redirect_uri = home_url('/?sua-action=google_callback');

        $response = wp_remote_post('https://oauth2.googleapis.com/token', [
            'body' => [
                'code'          => $code,
                'client_id'     => $client_id,
                'client_secret' => $client_secret,
                'redirect_uri'  => $redirect_uri,
                'grant_type'    => 'authorization_code',
            ],
        ]);

        if (is_wp_error($response)) {
            SUA_Logger::log('GOOGLE_LOGIN_FAILED', 'WP_Error saat menghubungi server Google: ' . $response->get_error_message(), null, $ip);
            SUA_Helpers::add_notice('Gagal terhubung ke server Google.');
            wp_redirect(SUA_Helpers::get_login_page_url());
            exit;
        }

        $token_data = json_decode(wp_remote_retrieve_body($response), true);
        if (empty($token_data['id_token'])) {
            SUA_Logger::log('GOOGLE_LOGIN_FAILED', 'Gagal mendapatkan id_token dari Google.', null, $ip);
            SUA_Helpers::add_notice('Gagal mendapatkan informasi pengguna dari Google.');
            wp_redirect(SUA_Helpers::get_login_page_url());
            exit;
        }

        list($header, $payload, $signature) = explode('.', $token_data['id_token']);
        $user_info = json_decode(base64_decode(str_replace(['-','_'],['+','/'], $payload)), true);

        if (empty($user_info['email'])) {
            SUA_Logger::log('GOOGLE_LOGIN_FAILED', 'Tidak ada email dalam payload id_token Google.', null, $ip);
            SUA_Helpers::add_notice('Tidak dapat menemukan alamat email dari akun Google Anda.');
            wp_redirect(SUA_Helpers::get_login_page_url());
            exit;
        }

        $email = sanitize_email($user_info['email']);
        $existing_user = get_user_by('email', $email);

        if ($existing_user) {
            $status = get_user_meta($existing_user->ID, 'membership_status', true);
            if ($status === 'banned') {
                SUA_Logger::log('GOOGLE_LOGIN_BANNED', 'Akun Google (email: ' . $email . ') diblokir.', $existing_user->ID, $ip);
                SUA_Helpers::add_notice('Akun Anda dengan email ini telah dinonaktifkan.');
                wp_redirect(SUA_Helpers::get_login_page_url());
                exit;
            }
            $user_id = $existing_user->ID;

        } else {
            // --- Registrasi Pengguna Baru via Google ---
            $first_name = $user_info['given_name'] ?? '';
            $last_name = $user_info['family_name'] ?? '';
            $display_name = $user_info['name'] ?? ($first_name . ' ' . $last_name);
            
            $username = SUA_Helpers::generate_unique_username();
            $user_id = wp_create_user($username, wp_generate_password(), $email);

            if (is_wp_error($user_id)) {
                SUA_Logger::log('GOOGLE_REGISTER_FAILED', 'Gagal wp_create_user (email: ' . $email . '): ' . $user_id->get_error_message(), null, $ip);
                SUA_Helpers::add_notice('Gagal membuat akun baru.');
                wp_redirect(SUA_Helpers::get_login_page_url());
                exit;
            }

            wp_update_user([
                'ID' => $user_id,
                'first_name' => $first_name,
                'last_name' => $last_name,
                'display_name' => $display_name,
            ]);

            update_user_meta($user_id, 'membership_status', 'active');
            update_user_meta($user_id, 'ekyc_status', 'unverified');
            
            if (SUA_Helpers::get_setting('record_user_ip')) {
                update_user_meta($user_id, 'ip_address', $ip);
            }

            SUA_Helpers::send_welcome_email($user_id);
            update_user_meta($user_id, '_sua_welcome_email_sent', 'yes');
            
            SUA_Logger::log('GOOGLE_REGISTER_SUCCESS', 'Akun baru dibuat via Google.', $user_id, $ip);
        }

        wp_set_current_user($user_id);
        wp_set_auth_cookie($user_id);
        SUA_Logger::log('GOOGLE_LOGIN_SUCCESS', 'Login Google berhasil.', $user_id, $ip);
        wp_redirect(SUA_Helpers::get_redirect_url_for_user($user_id));
        exit;
    }

    public function handle_email_register() {
        if (!$this->validate_form_submission('email', 'register')) {
            return;
        }
        
        $ip = SUA_Helpers::get_user_ip();
        $email = sanitize_email($_POST['sua_email']);

        // REVISI: Rate Limit Pendaftaran (Per IP, per Jam)
        $limit_reg_ip = (int) SUA_Helpers::get_setting('rate_limit_register_ip', 10); // Default 10
        if ($limit_reg_ip > 0) {
            $transient_key_ip = 'sua_reg_ip_' . md5($ip);
            $attempts_ip = (int) get_transient($transient_key_ip);

            if ($attempts_ip >= $limit_reg_ip) {
                SUA_Logger::log('REGISTER_RATE_LIMIT_IP', 'Batas pendaftaran per IP tercapai.', null, $ip);
                SUA_Helpers::add_notice('Anda telah mencapai batas pendaftaran per jam dari alamat IP ini.');
                return;
            }
            // Catat percobaan pendaftaran
            set_transient($transient_key_ip, $attempts_ip + 1, HOUR_IN_SECONDS);
        }
        
        $first_name = sanitize_text_field($_POST['sua_first_name']);
        $last_name = sanitize_text_field($_POST['sua_last_name']);

        if (!SUA_Helpers::is_email_domain_allowed($email)) {
            SUA_Logger::log('REGISTER_DOMAIN_BLOCKED', 'Domain email diblokir: ' . $email, null, $ip);
            SUA_Helpers::add_notice('Domain email tidak diizinkan untuk mendaftar.');
            return;
        }

        if (email_exists($email)) {
            SUA_Logger::log('REGISTER_EMAIL_EXISTS', 'Email sudah terdaftar: ' . $email, null, $ip);
            SUA_Helpers::add_notice('Alamat email ini sudah terdaftar. Silakan gunakan form login.');
            return;
        }

        $digits = SUA_Helpers::get_setting('otp_digits', 6);
        $otp = SUA_Helpers::generate_secure_otp($digits);
        
        $expiry_seconds = (int) SUA_Helpers::get_setting('otp_validity', 300);
        $otp_expiry_time = time() + $expiry_seconds;
        $otp_hash = wp_hash_password($otp);
        $wait_time = (int) SUA_Helpers::get_setting('otp_resend_wait', 60);

        // Kirim email OTP
        if (!SUA_Helpers::send_otp_email_direct($email, $first_name, $otp)) {
             SUA_Logger::log('REGISTER_OTP_SEND_FAILED', 'Gagal kirim OTP Email ke: ' . $email, null, $ip);
             SUA_Helpers::add_notice('Gagal mengirim email OTP. Silakan coba lagi.');
             return;
        }

        // Simpan data di transient
        $verification_key = wp_generate_password(32, false);
        $reg_data = [
            'type'         => 'email',
            'first_name'   => $first_name,
            'last_name'    => $last_name,
            'email'        => $email,
            'ip_address'   => $ip,
            'otp_hash'     => $otp_hash,
            'otp_expiry'   => $otp_expiry_time,
            'last_sent'    => time(),
            'wait_time'    => $wait_time,
            'otp_resend_limit' => (int) SUA_Helpers::get_setting('otp_rate_limit', 5),
            'otp_resend_count' => 0,
            'otp_resend_start' => time()
        ];
        
        set_transient('sua_reg_' . $verification_key, $reg_data, 10 * MINUTE_IN_SECONDS); 

        // Simpan kunci di Sesi
        unset($_SESSION['sua_verifying_user_id']); 
        $_SESSION['sua_verifying_reg_key'] = $verification_key;
        
        SUA_Logger::log('REGISTER_EMAIL_REQUEST', 'Permintaan registrasi email (OTP terkirim) untuk: ' . $email, null, $ip);
        wp_redirect(SUA_Helpers::get_verification_page_url());
        exit;
    }

    public function handle_email_login() {
        if (!$this->validate_form_submission('email', 'login')) {
            return;
        }

        $email = sanitize_email($_POST['sua_email']);
        $ip = SUA_Helpers::get_user_ip();

        // REVISI: Rate Limit Login Berlapis
        $limit_email = (int) SUA_Helpers::get_setting('rate_limit_login_email', 3); 
        $limit_ip = (int) SUA_Helpers::get_setting('rate_limit_login_ip', 6); 
        $period_minutes = (int) SUA_Helpers::get_setting('rate_limit_login_period', 10);
        $period_seconds = $period_minutes * MINUTE_IN_SECONDS;

        $transient_key_email = 'sua_login_email_' . md5($email);
        $transient_key_ip = 'sua_login_ip_' . md5($ip);

        $attempts_email = (int) get_transient($transient_key_email);
        $attempts_ip = (int) get_transient($transient_key_ip);

        if ( ($limit_email > 0 && $attempts_email >= $limit_email) || ($limit_ip > 0 && $attempts_ip >= $limit_ip) ) {
            SUA_Logger::log('LOGIN_RATE_LIMIT', 'Batas login tercapai untuk email: ' . $email, null, $ip);
            SUA_Helpers::add_notice('Anda telah mencapai batas permintaan login. Silakan coba lagi dalam ' . $period_minutes . ' menit.');
            return;
        }

        if ($limit_email > 0) {
            set_transient($transient_key_email, $attempts_email + 1, $period_seconds);
        }
        if ($limit_ip > 0) {
            set_transient($transient_key_ip, $attempts_ip + 1, $period_seconds);
        }
        
        $user = get_user_by('email', $email);

        if (!$user) {
            SUA_Logger::log('LOGIN_EMAIL_NOT_FOUND', 'Email tidak ditemukan: ' . $email, null, $ip);
            SUA_Helpers::add_notice('Alamat email tidak ditemukan.');
            return;
        }

        $status = get_user_meta($user->ID, 'membership_status', true);
        if ($status === 'banned') {
            SUA_Logger::log('LOGIN_BANNED', 'Akun diblokir mencoba login (Email): ' . $email, $user->ID, $ip);
            SUA_Helpers::add_notice('Akun Anda telah dinonaktifkan. Silakan hubungi administrator.');
            return;
        }

        if (SUA_Helpers::generate_and_send_otp($user->ID, 'email')) {
             SUA_Logger::log('LOGIN_EMAIL_REQUEST', 'Permintaan OTP login email sukses: ' . $email, $user->ID, $ip);
        } else {
             SUA_Logger::log('LOGIN_OTP_SEND_FAILED', 'Gagal kirim OTP login email: ' . $email, $user->ID, $ip);
             // Notice sudah di-set oleh helper
             return;
        }
        
        unset($_SESSION['sua_verifying_reg_key']); 
        $_SESSION['sua_verifying_user_id'] = $user->ID;

        wp_redirect(SUA_Helpers::get_verification_page_url());
        exit;
    }
    
    public function handle_whatsapp_register() {
        if (!$this->validate_form_submission('whatsapp', 'register')) {
            return;
        }

        $ip = SUA_Helpers::get_user_ip();

        // REVISI: Rate Limit Pendaftaran (Per IP, per Jam)
        $limit_reg_ip = (int) SUA_Helpers::get_setting('rate_limit_register_ip', 10); 
        if ($limit_reg_ip > 0) {
            $transient_key_ip = 'sua_reg_ip_' . md5($ip);
            $attempts_ip = (int) get_transient($transient_key_ip);

            if ($attempts_ip >= $limit_reg_ip) {
                SUA_Logger::log('REGISTER_RATE_LIMIT_IP', 'Batas pendaftaran per IP tercapai.', null, $ip);
                SUA_Helpers::add_notice('Anda telah mencapai batas pendaftaran per jam dari alamat IP ini.');
                return;
            }
            set_transient($transient_key_ip, $attempts_ip + 1, HOUR_IN_SECONDS);
        }

        $first_name = sanitize_text_field($_POST['sua_first_name']);
        $last_name = sanitize_text_field($_POST['sua_last_name']);
        $whatsapp_input = sanitize_text_field($_POST['sua_whatsapp']);

        // REVISI: Normalisasi nomor WA segera
        $whatsapp = preg_replace('/[^0-9]/', '', $whatsapp_input);
        $default_country_code = SUA_Helpers::get_setting('whatsapp_default_country_code');
        if (!empty($default_country_code) && substr($whatsapp, 0, 1) === '0') {
            $whatsapp = $default_country_code . substr($whatsapp, 1);
        }

        // REVISI: Periksa apakah WA (yang sudah dinormalisasi) sudah terdaftar
        if (get_users(['meta_key' => 'no_whatsapp', 'meta_value' => $whatsapp])) {
            SUA_Logger::log('REGISTER_WA_EXISTS', 'Nomor WA sudah terdaftar: ' . $whatsapp, null, $ip);
            SUA_Helpers::add_notice('Nomor WhatsApp ini sudah terdaftar. Silakan gunakan form login.');
            return;
        }

        $digits = SUA_Helpers::get_setting('otp_digits', 6);
        $otp = SUA_Helpers::generate_secure_otp($digits);
        
        $expiry_seconds = (int) SUA_Helpers::get_setting('otp_validity', 300);
        $otp_expiry_time = time() + $expiry_seconds;
        $otp_hash = wp_hash_password($otp);
        $wait_time = (int) SUA_Helpers::get_setting('otp_resend_wait', 60);

        // Kirim WA OTP
        $display_name = $first_name . ' ' . $last_name;
        if (!SUA_Helpers::send_otp_whatsapp_direct($whatsapp, $display_name, $otp)) {
            SUA_Logger::log('REGISTER_OTP_SEND_FAILED', 'Gagal kirim OTP WA ke: ' . $whatsapp, null, $ip);
            // send_otp_whatsapp_direct akan mengatur notice Gagal
            return;
        }

        // Simpan data di transient
        $verification_key = wp_generate_password(32, false);
        $reg_data = [
            'type'         => 'whatsapp',
            'first_name'   => $first_name,
            'last_name'    => $last_name,
            'whatsapp'     => $whatsapp,
            'ip_address'   => $ip,
            'otp_hash'     => $otp_hash,
            'otp_expiry'   => $otp_expiry_time,
            'last_sent'    => time(),
            'wait_time'    => $wait_time,
            'otp_resend_limit' => (int) SUA_Helpers::get_setting('otp_rate_limit', 5),
            'otp_resend_count' => 0,
            'otp_resend_start' => time()
        ];
        
        set_transient('sua_reg_' . $verification_key, $reg_data, 10 * MINUTE_IN_SECONDS);

        // Simpan kunci di Sesi
        unset($_SESSION['sua_verifying_user_id']);
        $_SESSION['sua_verifying_reg_key'] = $verification_key;
        
        SUA_Logger::log('REGISTER_WA_REQUEST', 'Permintaan registrasi WA (OTP terkirim) untuk: ' . $whatsapp, null, $ip);
        wp_redirect(SUA_Helpers::get_verification_page_url());
        exit;
    }

    public function handle_whatsapp_login() {
        if (!$this->validate_form_submission('whatsapp', 'login')) {
            return;
        }

        $whatsapp_input = sanitize_text_field($_POST['sua_whatsapp']);
        $ip = SUA_Helpers::get_user_ip();

        // REVISI: Rate Limit Login Berlapis
        $limit_wa = (int) SUA_Helpers::get_setting('rate_limit_login_whatsapp', 3);
        $limit_ip = (int) SUA_Helpers::get_setting('rate_limit_login_ip', 6);
        $period_minutes = (int) SUA_Helpers::get_setting('rate_limit_login_period', 10);
        $period_seconds = $period_minutes * MINUTE_IN_SECONDS;

        // REVISI: Normalisasi nomor WA sebelum query
        $whatsapp = preg_replace('/[^0-9]/', '', $whatsapp_input);
        $default_country_code = SUA_Helpers::get_setting('whatsapp_default_country_code');
        if (!empty($default_country_code) && substr($whatsapp, 0, 1) === '0') {
            $whatsapp = $default_country_code . substr($whatsapp, 1);
        }

        $transient_key_wa = 'sua_login_wa_' . md5($whatsapp);
        $transient_key_ip = 'sua_login_ip_' . md5($ip);

        $attempts_wa = (int) get_transient($transient_key_wa);
        $attempts_ip = (int) get_transient($transient_key_ip);

        if ( ($limit_wa > 0 && $attempts_wa >= $limit_wa) || ($limit_ip > 0 && $attempts_ip >= $limit_ip) ) {
            SUA_Logger::log('LOGIN_RATE_LIMIT', 'Batas login tercapai untuk WA: ' . $whatsapp, null, $ip);
            SUA_Helpers::add_notice('Anda telah mencapai batas permintaan login. Silakan coba lagi dalam ' . $period_minutes . ' menit.');
            return;
        }

        if ($limit_wa > 0) {
            set_transient($transient_key_wa, $attempts_wa + 1, $period_seconds);
        }
        if ($limit_ip > 0) {
            set_transient($transient_key_ip, $attempts_ip + 1, $period_seconds);
        }
        
        $users = get_users(['meta_key' => 'no_whatsapp', 'meta_value' => $whatsapp]);

        if (empty($users)) {
            SUA_Logger::log('LOGIN_WA_NOT_FOUND', 'Nomor WA tidak ditemukan: ' . $whatsapp, null, $ip);
            SUA_Helpers::add_notice('Nomor WhatsApp tidak ditemukan.');
            return;
        }

        $user = $users[0];

        $status = get_user_meta($user->ID, 'membership_status', true);
        if ($status === 'banned') {
            SUA_Logger::log('LOGIN_BANNED', 'Akun diblokir mencoba login (WA): ' . $whatsapp, $user->ID, $ip);
            SUA_Helpers::add_notice('Akun Anda telah dinonaktifkan. Silakan hubungi administrator.');
            return;
        }

        if (SUA_Helpers::generate_and_send_otp($user->ID, 'whatsapp')) {
             SUA_Logger::log('LOGIN_WA_REQUEST', 'Permintaan OTP login WA sukses: ' . $whatsapp, $user->ID, $ip);
        } else {
             SUA_Logger::log('LOGIN_OTP_SEND_FAILED', 'Gagal kirim OTP login WA: ' . $whatsapp, $user->ID, $ip);
             // Notice sudah di-set oleh helper
             return;
        }
        
        unset($_SESSION['sua_verifying_reg_key']); 
        $_SESSION['sua_verifying_user_id'] = $user->ID;

        wp_redirect(SUA_Helpers::get_verification_page_url());
        exit;
    }

    public function handle_otp_verify() {
        $ip = SUA_Helpers::get_user_ip();

        if (!isset($_POST['sua_otp_verify_nonce']) || !wp_verify_nonce($_POST['sua_otp_verify_nonce'], 'sua_otp_verify_action')) {
            SUA_Logger::log('OTP_VERIFY_NONCE_FAILED', 'Pemeriksaan Nonce OTP Gagal.', null, $ip);
            SUA_Helpers::add_notice('Sesi tidak valid. Silakan coba lagi.');
            return;
        }

        if (empty($_POST['sua_otp_code'])) {
            SUA_Logger::log('OTP_VERIFY_EMPTY', 'Kode OTP dikirim kosong.', null, $ip);
            SUA_Helpers::add_notice('Harap masukkan kode OTP Anda.');
            return;
        }

        $otp_code = sanitize_text_field($_POST['sua_otp_code']);
        $limit_attempts = (int) SUA_Helpers::get_setting('rate_limit_otp_attempts', 3); 

        // ALUR 1: PENGGUNA SEDANG LOGIN (User ID ada di Sesi)
        if (isset($_SESSION['sua_verifying_user_id'])) {
            $user_id = $_SESSION['sua_verifying_user_id'];
            
            if (!$user_id) {
                 SUA_Logger::log('OTP_VERIFY_NO_SESSION', 'Verifikasi OTP gagal, tidak ada user_id di sesi.', null, $ip);
                 SUA_Helpers::add_notice('Sesi verifikasi Anda telah berakhir. Silakan coba lagi.');
                 unset($_SESSION['sua_verifying_user_id']);
                 return;
            }

            $stored_otp_hash = get_user_meta($user_id, 'sua_otp_code', true);
            $otp_expiry = get_user_meta($user_id, 'sua_otp_expiry', true);

            // Periksa OTP
            if ($stored_otp_hash && wp_check_password($otp_code, $stored_otp_hash, $user_id) && time() < $otp_expiry) {
                // OTP BERHASIL
                delete_user_meta($user_id, 'sua_otp_code');
                delete_user_meta($user_id, 'sua_otp_expiry');
                delete_user_meta($user_id, 'sua_otp_last_sent');
                delete_user_meta($user_id, '_sua_otp_rate_limit_data');
                
                unset($_SESSION['sua_verifying_user_id']);
                unset($_SESSION['sua_otp_failed_attempts']); 
                
                if (session_status() === PHP_SESSION_ACTIVE) {
                    session_regenerate_id(true);
                }

                wp_set_current_user($user_id);
                wp_set_auth_cookie($user_id);
                
                $welcome_sent = get_user_meta($user_id, '_sua_welcome_email_sent', true);
                if ($welcome_sent !== 'yes') {
                    SUA_Helpers::send_welcome_email($user_id);
                    update_user_meta($user_id, '_sua_welcome_email_sent', 'yes');
                }

                // Hapus transient rate limit login
                $user_data = get_userdata($user_id);
                if ($user_data && $user_data->user_email) {
                    delete_transient('sua_login_email_' . md5($user_data->user_email));
                }
                $whatsapp_no = get_user_meta($user_id, 'no_whatsapp', true);
                if ($whatsapp_no) {
                    delete_transient('sua_login_wa_' . md5($whatsapp_no));
                }
                delete_transient('sua_login_ip_' . md5($ip));

                SUA_Logger::log('OTP_LOGIN_SUCCESS', 'Verifikasi OTP login berhasil.', $user_id, $ip);
                wp_redirect(SUA_Helpers::get_redirect_url_for_user($user_id));
                exit;

            } else {
                // OTP GAGAL (Rate Limit Percobaan)
                if ($limit_attempts > 0) {
                    if (!isset($_SESSION['sua_otp_failed_attempts'])) {
                        $_SESSION['sua_otp_failed_attempts'] = 0;
                    }
                    $_SESSION['sua_otp_failed_attempts']++;

                    if ($_SESSION['sua_otp_failed_attempts'] >= $limit_attempts) {
                        delete_user_meta($user_id, 'sua_otp_code');
                        delete_user_meta($user_id, 'sua_otp_expiry');
                        unset($_SESSION['sua_verifying_user_id']);
                        unset($_SESSION['sua_otp_failed_attempts']);

                        SUA_Logger::log('OTP_LOGIN_FAILED_LIMIT', 'Verifikasi OTP login gagal, batas percobaan tercapai.', $user_id, $ip);
                        SUA_Helpers::add_notice('Anda telah ' . $limit_attempts . ' kali salah memasukkan OTP. Sesi verifikasi dibatalkan. Silakan ulangi proses login.');
                        wp_redirect(SUA_Helpers::get_login_page_url());
                        exit;
                    } else {
                        $remaining = $limit_attempts - $_SESSION['sua_otp_failed_attempts'];
                        SUA_Logger::log('OTP_LOGIN_FAILED_ATTEMPT', 'Verifikasi OTP login gagal (percobaan salah). Sisa: ' . $remaining, $user_id, $ip);
                        SUA_Helpers::add_notice('Kode OTP tidak valid. Sisa percobaan: ' . $remaining);
                    }
                } else {
                    SUA_Logger::log('OTP_LOGIN_FAILED_ATTEMPT', 'Verifikasi OTP login gagal (percobaan salah).', $user_id, $ip);
                    SUA_Helpers::add_notice('Kode OTP tidak valid atau telah kedaluwarsa.');
                }
            }

        } 
        // ALUR 2: PENGGUNA SEDANG REGISTRASI (Kunci Transient ada di Sesi)
        elseif (isset($_SESSION['sua_verifying_reg_key'])) {
            $verification_key = $_SESSION['sua_verifying_reg_key'];
            $transient_key = 'sua_reg_' . $verification_key;
            $reg_data = get_transient($transient_key);

            if (false === $reg_data) {
                SUA_Logger::log('OTP_REG_SESSION_EXPIRED', 'Sesi transient registrasi tidak ditemukan (kedaluwarsa).', null, $ip);
                SUA_Helpers::add_notice('Sesi pendaftaran Anda telah kedaluwarsa. Silakan ulangi pendaftaran.');
                unset($_SESSION['sua_verifying_reg_key']);
                return;
            }
            
            // Ambil IP dari data transient untuk logging
            $reg_ip = $reg_data['ip_address'] ?? $ip;

            // Periksa OTP
            if (wp_check_password($otp_code, $reg_data['otp_hash']) && time() < $reg_data['otp_expiry']) {
                // OTP BERHASIL - Buat Akun Pengguna
                
                $email = $reg_data['email'] ?? '';
                $whatsapp = $reg_data['whatsapp'] ?? '';
                $username = SUA_Helpers::generate_unique_username();
                $user_id = wp_create_user($username, wp_generate_password(), $email);

                if (is_wp_error($user_id)) {
                    SUA_Logger::log('OTP_REG_FAILED', 'Gagal wp_create_user saat verifikasi: ' . $user_id->get_error_message(), null, $reg_ip);
                    SUA_Helpers::add_notice('Gagal membuat akun Anda. Silakan coba lagi. ' . $user_id->get_error_message());
                    return;
                }

                wp_update_user([
                    'ID' => $user_id,
                    'first_name' => $reg_data['first_name'],
                    'last_name' => $reg_data['last_name'],
                    'display_name' => $reg_data['first_name'] . ' ' . $reg_data['last_name'],
                ]);
                
                if (!empty($whatsapp)) {
                    update_user_meta($user_id, 'no_whatsapp', $whatsapp);
                }
                update_user_meta($user_id, 'membership_status', 'active');
                update_user_meta($user_id, 'ekyc_status', 'unverified');
                update_user_meta($user_id, '_sua_welcome_email_sent', 'no');
                if (SUA_Helpers::get_setting('record_user_ip')) {
                    update_user_meta($user_id, 'ip_address', $reg_ip);
                }

                delete_transient($transient_key);
                unset($_SESSION['sua_verifying_reg_key']);
                
                if (session_status() === PHP_SESSION_ACTIVE) {
                    session_regenerate_id(true);
                }

                // Login dan Redirect
                wp_set_current_user($user_id);
                wp_set_auth_cookie($user_id);

                $welcome_sent = get_user_meta($user_id, '_sua_welcome_email_sent', true);
                if ($welcome_sent !== 'yes') {
                    SUA_Helpers::send_welcome_email($user_id);
                    update_user_meta($user_id, '_sua_welcome_email_sent', 'yes');
                }

                SUA_Logger::log('OTP_REG_SUCCESS', 'Verifikasi OTP registrasi berhasil, akun dibuat.', $user_id, $reg_ip);
                wp_redirect(SUA_Helpers::get_redirect_url_for_user($user_id));
                exit;

            } else {
                // OTP GAGAL (Rate Limit Percobaan)
                if ($limit_attempts > 0) {
                    $failed_attempts = (int) ($reg_data['failed_attempts'] ?? 0) + 1;

                    if ($failed_attempts >= $limit_attempts) {
                        delete_transient($transient_key);
                        unset($_SESSION['sua_verifying_reg_key']);
                        SUA_Logger::log('OTP_REG_FAILED_LIMIT', 'Verifikasi OTP registrasi gagal, batas percobaan tercapai.', null, $reg_ip);
                        SUA_Helpers::add_notice('Anda telah ' . $limit_attempts . ' kali salah memasukkan OTP. Sesi pendaftaran dibatalkan. Silakan ulangi pendaftaran.');
                        wp_redirect(SUA_Helpers::get_login_page_url());
                        exit;
                    } else {
                        $reg_data['failed_attempts'] = $failed_attempts;
                        set_transient($transient_key, $reg_data, 10 * MINUTE_IN_SECONDS);
                        
                        $remaining = $limit_attempts - $failed_attempts;
                        SUA_Logger::log('OTP_REG_FAILED_ATTEMPT', 'Verifikasi OTP registrasi gagal (percobaan salah). Sisa: ' . $remaining, null, $reg_ip);
                        SUA_Helpers::add_notice('Kode OTP tidak valid. Sisa percobaan: ' . $remaining);
                    }
                } else {
                    SUA_Logger::log('OTP_REG_FAILED_ATTEMPT', 'Verifikasi OTP registrasi gagal (percobaan salah).', null, $reg_ip);
                    SUA_Helpers::add_notice('Kode OTP tidak valid atau telah kedaluwarsa.');
                }
            }

        } 
        // TIDAK ADA SESI
        else {
            SUA_Logger::log('OTP_VERIFY_NO_SESSION', 'Verifikasi OTP gagal, tidak ada sesi (user_id atau reg_key).', null, $ip);
            SUA_Helpers::add_notice('Sesi verifikasi Anda telah berakhir. Silakan coba lagi.');
        }
    }

    public function handle_ajax_resend_otp() {

        // PERBAIKAN: Mulai sesi secara manual KHUSUS UNTUK AJAX ini.
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        
        $ip = SUA_Helpers::get_user_ip(); // Dapatkan IP untuk logging

        if (!isset($_POST['nonce']) || !wp_verify_nonce($_POST['nonce'], 'sua_resend_otp_nonce')) {
            SUA_Logger::log('OTP_RESEND_NONCE_FAILED', 'Pemeriksaan Nonce Kirim Ulang OTP Gagal.', null, $ip);
            wp_send_json_error(['message' => 'Pemeriksaan keamanan gagal.']);
        }

        // ALUR 1: PENGGUNA SEDANG LOGIN
        if (isset($_SESSION['sua_verifying_user_id'])) {
            $user_id = $_SESSION['sua_verifying_user_id'];
            if (!$user_id) {
                SUA_Logger::log('OTP_RESEND_SESSION_EXPIRED', 'Sesi login kirim ulang OTP tidak valid (user_id kosong).', null, $ip);
                wp_send_json_error(['message' => 'Sesi verifikasi Anda telah berakhir. Silakan muat ulang halaman.']);
            }
            
            // Logika rate limit kirim ulang (dari user_meta)
            $rate_limit = (int) SUA_Helpers::get_setting('otp_rate_limit', 5);
            if ($rate_limit > 0) {
                $limit_data = get_user_meta($user_id, '_sua_otp_rate_limit_data', true);
                if (!is_array($limit_data)) {
                    $limit_data = ['count' => 0, 'start_time' => time()];
                }
                $reset_time_minutes = (int) SUA_Helpers::get_setting('otp_rate_limit_reset', 60);
                $reset_time_seconds = $reset_time_minutes * MINUTE_IN_SECONDS;

                if (time() > $limit_data['start_time'] + $reset_time_seconds) {
                    $limit_data = ['count' => 0, 'start_time' => time()];
                }
                if ($limit_data['count'] >= $rate_limit) {
                    SUA_Logger::log('OTP_RESEND_RATE_LIMIT', 'Batas kirim ulang OTP (login) tercapai.', $user_id, $ip);
                    wp_send_json_error(['message' => 'Anda telah mencapai batas permintaan OTP. Silakan coba lagi nanti.']);
                }
                $limit_data['count']++;
                update_user_meta($user_id, '_sua_otp_rate_limit_data', $limit_data);
            }
            
            $user = get_userdata($user_id);
            $method = !empty($user->user_email) ? 'email' : 'whatsapp';

            $last_sent = get_user_meta($user_id, 'sua_otp_last_sent', true);
            $wait_time = (int) SUA_Helpers::get_setting('otp_resend_wait', 60);
            if ($last_sent && (time() - $last_sent) < $wait_time) {
                SUA_Logger::log('OTP_RESEND_WAIT_TIME', 'Permintaan kirim ulang OTP (login) terlalu cepat.', $user_id, $ip);
                wp_send_json_error(['message' => 'Harap tunggu sebelum meminta kode baru.']);
            }

            if (SUA_Helpers::generate_and_send_otp($user_id, $method)) {
                SUA_Logger::log('OTP_RESEND_LOGIN_SUCCESS', 'Kirim ulang OTP (login) berhasil.', $user_id, $ip);
                wp_send_json_success(['message' => 'Kode OTP baru telah berhasil dikirim.']);
            } else {
                SUA_Logger::log('OTP_RESEND_LOGIN_FAILED', 'Gagal kirim ulang OTP (login) oleh helper.', $user_id, $ip);
                wp_send_json_error(['message' => 'Gagal mengirim kode OTP. Silakan coba lagi nanti.']);
            }

        }
        // ALUR 2: PENGGUNA SEDANG REGISTRASI
        elseif (isset($_SESSION['sua_verifying_reg_key'])) {
            $verification_key = $_SESSION['sua_verifying_reg_key'];
            $transient_key = 'sua_reg_' . $verification_key;
            $reg_data = get_transient($transient_key);

            if (false === $reg_data) {
                SUA_Logger::log('OTP_RESEND_SESSION_EXPIRED', 'Sesi registrasi kirim ulang OTP tidak valid (transient hilang).', null, $ip);
                wp_send_json_error(['message' => 'Sesi pendaftaran Anda telah berakhir. Silakan muat ulang halaman.']);
            }
            
            $reg_ip = $reg_data['ip_address'] ?? $ip; // Gunakan IP asli dari transient

            // Cek waktu tunggu
            if (isset($reg_data['last_sent']) && (time() - $reg_data['last_sent']) < $reg_data['wait_time']) {
                 SUA_Logger::log('OTP_RESEND_WAIT_TIME', 'Permintaan kirim ulang OTP (reg) terlalu cepat.', null, $reg_ip);
                 wp_send_json_error(['message' => 'Harap tunggu sebelum meminta kode baru.']);
            }

            // Cek rate limit (disimpan di transient)
            $reset_time_minutes = (int) SUA_Helpers::get_setting('otp_rate_limit_reset', 60);
            $reset_time_seconds = $reset_time_minutes * MINUTE_IN_SECONDS;
            
            if (time() > $reg_data['otp_resend_start'] + $reset_time_seconds) {
                $reg_data['otp_resend_count'] = 0;
                $reg_data['otp_resend_start'] = time();
            }

            if ($reg_data['otp_resend_count'] >= $reg_data['otp_resend_limit']) {
                 SUA_Logger::log('OTP_RESEND_RATE_LIMIT', 'Batas kirim ulang OTP (reg) tercapai.', null, $reg_ip);
                 wp_send_json_error(['message' => 'Anda telah mencapai batas permintaan OTP. Silakan coba lagi nanti.']);
            }

            // Buat OTP baru
            $digits = SUA_Helpers::get_setting('otp_digits', 6);
            $otp = SUA_Helpers::generate_secure_otp($digits);
            $expiry_seconds = (int) SUA_Helpers::get_setting('otp_validity', 300);
            
            // Kirim OTP baru
            $sent = false;
            $method = $reg_data['type'];
            if ($method === 'email') {
                $sent = SUA_Helpers::send_otp_email_direct($reg_data['email'], $reg_data['first_name'], $otp);
            } elseif ($method === 'whatsapp') {
                $display_name = $reg_data['first_name'] . ' ' . $reg_data['last_name'];
                $sent = SUA_Helpers::send_otp_whatsapp_direct($reg_data['whatsapp'], $display_name, $otp);
            }

            if ($sent) {
                // Update transient dengan data OTP baru
                $reg_data['otp_hash'] = wp_hash_password($otp);
                $reg_data['otp_expiry'] = time() + $expiry_seconds;
                $reg_data['last_sent'] = time();
                $reg_data['otp_resend_count']++;
                unset($reg_data['failed_attempts']); 
                
                set_transient($transient_key, $reg_data, 10 * MINUTE_IN_SECONDS);
                SUA_Logger::log('OTP_RESEND_REG_SUCCESS', 'Kirim ulang OTP (reg) via ' . $method . ' berhasil.', null, $reg_ip);
                wp_send_json_success(['message' => 'Kode OTP baru telah berhasil dikirim.']);
            } else {
                SUA_Logger::log('OTP_RESEND_REG_FAILED', 'Gagal kirim ulang OTP (reg) via ' . $method . ' oleh helper.', null, $reg_ip);
                wp_send_json_error(['message' => 'Gagal mengirim kode OTP. Silakan coba lagi nanti.']);
            }

        }
        // TIDAK ADA SESI
        else {
            SUA_Logger::log('OTP_RESEND_NO_SESSION', 'Permintaan kirim ulang OTP gagal, tidak ada sesi.', null, $ip);
            wp_send_json_error(['message' => 'Sesi verifikasi Anda telah berakhir. Silakan muat ulang halaman.']);
        }
    }
}