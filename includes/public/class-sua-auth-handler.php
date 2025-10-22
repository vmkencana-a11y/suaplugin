<?php
/**
 * File: class-sua-auth-handler.php
 * Status: VERIFIED & REVISED
 * Revision Note:
 * - This file restores the use of `wp_check_password()` in the `handle_otp_verify()` function.
 * - This ensures that the submitted plaintext OTP is correctly compared against the hashed OTP stored in the database, fixing the "Invalid OTP" bug.
 * - No other functions in this file have been altered.
 *
 * @package    Simple_User_Access
 * @subpackage Simple_User_Access/public
 */
class SUA_Auth_Handler {

    public function __construct() {
        // Session start is correctly handled
    }

    private function validate_form_submission($form_type, $action_type) {
        if (SUA_Helpers::get_setting("{$form_type}_enable_nonce")) {
            $nonce = $_POST["sua_{$form_type}_{$action_type}_nonce"] ?? '';
            $action = "sua_{$form_type}_{$action_type}_action";
            if (!wp_verify_nonce($nonce, $action)) {
                SUA_Helpers::add_notice('Sesi tidak valid atau telah kedaluwarsa. Silakan muat ulang halaman dan coba lagi.');
                return false;
            }
        }

        if (SUA_Helpers::get_setting("{$form_type}_enable_recaptcha")) {
            $token = $_POST['recaptcha_token'] ?? '';
            if (empty($token)) {
                SUA_Helpers::add_notice('Token reCAPTCHA tidak ditemukan. Silakan coba lagi.');
                return false;
            }
            if (!SUA_Helpers::verify_recaptcha($token)) {
                SUA_Helpers::add_notice('Verifikasi reCAPTCHA gagal. Anda mungkin terdeteksi sebagai bot.');
                return false;
            }
        }

        $required_fields = [];
        if ($action_type === 'register') {
            $required_fields = ['sua_first_name', 'sua_last_name'];
        }
        $field_key = $form_type === 'whatsapp' ? 'sua_whatsapp' : 'sua_email';
        $required_fields[] = $field_key;

        foreach ($required_fields as $field) {
            if (empty($_POST[$field])) {
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
            SUA_Helpers::add_notice('Google Login tidak dikonfigurasi dengan benar oleh admin.');
            wp_redirect(SUA_Helpers::get_login_page_url());
            exit;
        }

        $auth_url = 'https://accounts.google.com/o/oauth2/v2/auth?' . http_build_query([
            'client_id' => $client_id,
            'redirect_uri' => $redirect_uri,
            'response_type' => 'code',
            'scope' => 'openid email profile',
            'prompt' => 'select_account'
        ]);

        wp_redirect($auth_url);
        exit;
    }
    
    public function handle_google_callback() {
        if (!isset($_GET['code'])) {
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
            SUA_Helpers::add_notice('Gagal terhubung ke server Google.');
            wp_redirect(SUA_Helpers::get_login_page_url());
            exit;
        }

        $token_data = json_decode(wp_remote_retrieve_body($response), true);
        if (empty($token_data['id_token'])) {
            SUA_Helpers::add_notice('Gagal mendapatkan informasi pengguna dari Google.');
            wp_redirect(SUA_Helpers::get_login_page_url());
            exit;
        }

        list($header, $payload, $signature) = explode('.', $token_data['id_token']);
        $user_info = json_decode(base64_decode(str_replace(['-','_'],['+','/'], $payload)), true);

        if (empty($user_info['email'])) {
            SUA_Helpers::add_notice('Tidak dapat menemukan alamat email dari akun Google Anda.');
            wp_redirect(SUA_Helpers::get_login_page_url());
            exit;
        }

        $email = sanitize_email($user_info['email']);
        $existing_user = get_user_by('email', $email);

        if ($existing_user) {
            $status = get_user_meta($existing_user->ID, 'membership_status', true);
            if ($status === 'banned') {
                SUA_Helpers::add_notice('Akun Anda dengan email ini telah dinonaktifkan.');
                wp_redirect(SUA_Helpers::get_login_page_url());
                exit;
            }
            $user_id = $existing_user->ID;

        } else {
            $first_name = $user_info['given_name'] ?? '';
            $last_name = $user_info['family_name'] ?? '';
            $display_name = $user_info['name'] ?? ($first_name . ' ' . $last_name);
            
            $username = SUA_Helpers::generate_unique_username();
            $user_id = wp_create_user($username, wp_generate_password(), $email);

            if (is_wp_error($user_id)) {
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
                update_user_meta($user_id, 'ip_address', SUA_Helpers::get_user_ip());
            }

            SUA_Helpers::send_welcome_email($user_id);
            update_user_meta($user_id, '_sua_welcome_email_sent', 'yes');
        }

        wp_set_current_user($user_id);
        wp_set_auth_cookie($user_id);
        wp_redirect(SUA_Helpers::get_redirect_url_for_user($user_id));
        exit;
    }

    public function handle_email_register() {
        if (!$this->validate_form_submission('email', 'register')) {
            return;
        }

        $first_name = sanitize_text_field($_POST['sua_first_name']);
        $last_name = sanitize_text_field($_POST['sua_last_name']);
        $email = sanitize_email($_POST['sua_email']);

        if (!SUA_Helpers::is_email_domain_allowed($email)) {
            SUA_Helpers::add_notice('Domain email tidak diizinkan untuk mendaftar.');
            return;
        }

        if (email_exists($email)) {
            SUA_Helpers::add_notice('Alamat email ini sudah terdaftar.');
            return;
        }

        $username = SUA_Helpers::generate_unique_username();
        $user_id = wp_create_user($username, wp_generate_password(), $email);

        if (is_wp_error($user_id)) {
            SUA_Helpers::add_notice('Gagal membuat akun. Silakan coba lagi.');
            return;
        }

        wp_update_user([
            'ID' => $user_id,
            'first_name' => $first_name,
            'last_name' => $last_name,
            'display_name' => $first_name . ' ' . $last_name,
        ]);
        
        update_user_meta($user_id, 'membership_status', 'active');
        update_user_meta($user_id, 'ekyc_status', 'unverified');
        update_user_meta($user_id, '_sua_welcome_email_sent', 'no');

        if (SUA_Helpers::get_setting('record_user_ip')) {
            update_user_meta($user_id, 'ip_address', SUA_Helpers::get_user_ip());
        }

        SUA_Helpers::generate_and_send_otp($user_id, 'email');
        $_SESSION['sua_verifying_user_id'] = $user_id;
        
        wp_redirect(SUA_Helpers::get_verification_page_url());
        exit;
    }

    public function handle_email_login() {
        if (!$this->validate_form_submission('email', 'login')) {
            return;
        }

        $email = sanitize_email($_POST['sua_email']);
        $user = get_user_by('email', $email);

        if (!$user) {
            SUA_Helpers::add_notice('Alamat email tidak ditemukan.');
            return;
        }

        $status = get_user_meta($user->ID, 'membership_status', true);
        if ($status === 'banned') {
            SUA_Helpers::add_notice('Akun Anda telah dinonaktifkan. Silakan hubungi administrator.');
            return;
        }

        SUA_Helpers::generate_and_send_otp($user->ID, 'email');
        $_SESSION['sua_verifying_user_id'] = $user->ID;

        wp_redirect(SUA_Helpers::get_verification_page_url());
        exit;
    }
    
    public function handle_whatsapp_register() {
        if (!$this->validate_form_submission('whatsapp', 'register')) {
            return;
        }

        $first_name = sanitize_text_field($_POST['sua_first_name']);
        $last_name = sanitize_text_field($_POST['sua_last_name']);
        $whatsapp = sanitize_text_field($_POST['sua_whatsapp']);

        if (get_users(['meta_key' => 'no_whatsapp', 'meta_value' => $whatsapp])) {
            SUA_Helpers::add_notice('Nomor WhatsApp ini sudah terdaftar.');
            return;
        }

        $username = SUA_Helpers::generate_unique_username();
        $user_id = wp_create_user($username, wp_generate_password(), '');

        if (is_wp_error($user_id)) {
            SUA_Helpers::add_notice('Gagal membuat akun. Silakan coba lagi.');
            return;
        }

        wp_update_user([
            'ID' => $user_id,
            'first_name' => $first_name,
            'last_name' => $last_name,
            'display_name' => $first_name . ' ' . $last_name,
        ]);
        
        update_user_meta($user_id, 'no_whatsapp', $whatsapp);
        update_user_meta($user_id, 'membership_status', 'active');
        update_user_meta($user_id, 'ekyc_status', 'unverified');
        update_user_meta($user_id, '_sua_welcome_email_sent', 'no');

        if (SUA_Helpers::get_setting('record_user_ip')) {
            update_user_meta($user_id, 'ip_address', SUA_Helpers::get_user_ip());
        }

        SUA_Helpers::generate_and_send_otp($user_id, 'whatsapp');
        $_SESSION['sua_verifying_user_id'] = $user_id;
        
        wp_redirect(SUA_Helpers::get_verification_page_url());
        exit;
    }

    public function handle_whatsapp_login() {
        if (!$this->validate_form_submission('whatsapp', 'login')) {
            return;
        }

        $whatsapp = sanitize_text_field($_POST['sua_whatsapp']);
        $users = get_users(['meta_key' => 'no_whatsapp', 'meta_value' => $whatsapp]);

        if (empty($users)) {
            SUA_Helpers::add_notice('Nomor WhatsApp tidak ditemukan.');
            return;
        }

        $user = $users[0];

        $status = get_user_meta($user->ID, 'membership_status', true);
        if ($status === 'banned') {
            SUA_Helpers::add_notice('Akun Anda telah dinonaktifkan. Silakan hubungi administrator.');
            return;
        }

        SUA_Helpers::generate_and_send_otp($user->ID, 'whatsapp');
        $_SESSION['sua_verifying_user_id'] = $user->ID;

        wp_redirect(SUA_Helpers::get_verification_page_url());
        exit;
    }

    public function handle_otp_verify() {
        if (!isset($_POST['sua_otp_verify_nonce']) || !wp_verify_nonce($_POST['sua_otp_verify_nonce'], 'sua_otp_verify_action')) {
            SUA_Helpers::add_notice('Sesi tidak valid. Silakan coba lagi.');
            return;
        }

        if (empty($_POST['sua_otp_code'])) {
            SUA_Helpers::add_notice('Harap masukkan kode OTP Anda.');
            return;
        }

        $user_id = $_SESSION['sua_verifying_user_id'] ?? null;
        $otp_code = sanitize_text_field($_POST['sua_otp_code']);

        if (!$user_id) {
            SUA_Helpers::add_notice('Sesi verifikasi Anda telah berakhir. Silakan coba lagi.');
            return;
        }

        $stored_otp_hash = get_user_meta($user_id, 'sua_otp_code', true);
        $otp_expiry = get_user_meta($user_id, 'sua_otp_expiry', true);

        if ($stored_otp_hash && wp_check_password($otp_code, $stored_otp_hash, $user_id) && time() < $otp_expiry) {
            delete_user_meta($user_id, 'sua_otp_code');
            delete_user_meta($user_id, 'sua_otp_expiry');
            delete_user_meta($user_id, 'sua_otp_last_sent');
            delete_user_meta($user_id, '_sua_otp_rate_limit_data');
            
            unset($_SESSION['sua_verifying_user_id']);

            wp_set_current_user($user_id);
            wp_set_auth_cookie($user_id);
            
            $welcome_sent = get_user_meta($user_id, '_sua_welcome_email_sent', true);
            if ($welcome_sent !== 'yes') {
                SUA_Helpers::send_welcome_email($user_id);
                update_user_meta($user_id, '_sua_welcome_email_sent', 'yes');
            }

            wp_redirect(SUA_Helpers::get_redirect_url_for_user($user_id));
            exit;
        } else {
            SUA_Helpers::add_notice('Kode OTP tidak valid atau telah kedaluwarsa.');
        }
    }

    public function handle_ajax_resend_otp() {
        if (!isset($_POST['nonce']) || !wp_verify_nonce($_POST['nonce'], 'sua_resend_otp_nonce')) {
            wp_send_json_error(['message' => 'Pemeriksaan keamanan gagal.']);
        }
        
        $user_id = $_SESSION['sua_verifying_user_id'] ?? null;
        if (!$user_id) {
            wp_send_json_error(['message' => 'Sesi verifikasi Anda telah berakhir. Silakan muat ulang halaman.']);
        }
        
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
             wp_send_json_error(['message' => 'Harap tunggu sebelum meminta kode baru.']);
        }

        if (SUA_Helpers::generate_and_send_otp($user_id, $method)) {
            wp_send_json_success(['message' => 'Kode OTP baru telah berhasil dikirim.']);
        } else {
            wp_send_json_error(['message' => 'Gagal mengirim kode OTP. Silakan coba lagi nanti.']);
        }
    }
}
