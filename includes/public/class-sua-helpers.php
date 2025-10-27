<?php
/**
 * File: class-sua-helpers.php
 * Status: VERIFIED & REVISED
 * Revision Note:
 * - This file restores the critical security hardening for OTP generation and storage.
 * - `generate_and_send_otp()` now correctly uses `random_int()` for secure random number generation.
 * - It also now correctly stores the OTP as a hash using `wp_hash_password()`, fixing the "Invalid OTP" bug.
 * - No other functions in this file have been altered.
 *
 * @package    Simple_User_Access
 * @subpackage Simple_User_Access/public
 */
class SUA_Helpers {
    
    public static function get_setting($key, $default = '') {
        $options = get_option('sua_settings');
        return isset($options[$key]) && $options[$key] !== '' ? $options[$key] : $default;
    }

    public static function log_error($message) {
        if (defined('WP_DEBUG') && WP_DEBUG === true && defined('WP_DEBUG_LOG') && WP_DEBUG_LOG) {
            error_log('Simple User Access Error: ' . $message);
        }
    }

    public static function add_notice($message, $type = 'error') {
        $notices = get_transient('sua_notices') ?: [];
        $notices[] = ['message' => $message, 'type' => $type];
        set_transient('sua_notices', $notices, 60);
    }
    
    public static function display_notices() {
        $notices = get_transient('sua_notices');
        if (!empty($notices)) {
            foreach ($notices as $notice) {
                echo '<div class="sua-notice sua-notice-' . esc_attr($notice['type']) . '">' . wp_kses_post($notice['message']) . '</div>';
            }
            delete_transient('sua_notices');
        }
    }

    public static function get_login_page_url() {
        $page_id = self::get_setting('login_page');
        return $page_id ? get_permalink($page_id) : home_url('/');
    }
    
    public static function get_verification_page_url() {
        $page_id = self::get_setting('verification_page');
        return $page_id ? get_permalink($page_id) : self::get_login_page_url();
    }

    public static function get_redirect_url_for_user($user_id) {
        $user = get_userdata($user_id);
        if (!$user) {
            return home_url('/');
        }
        $role = $user->roles[0] ?? 'subscriber';

        if ($role === 'administrator') {
            $redirect_page_id = self::get_setting('redirect_administrator');
            return $redirect_page_id ? get_permalink($redirect_page_id) : admin_url();
        }

        $redirect_page_id = self::get_setting('redirect_' . $role);
        
        if ($redirect_page_id) {
            return get_permalink($redirect_page_id);
        }
        
        return home_url('/');
    }
    
    public static function generate_unique_username($prefix = 'ID') {
        do {
            $username = $prefix . mt_rand(1000000000, 9999999999);
        } while (username_exists($username));
        return $username;
    }

    /**
     * REVISI: Helper baru untuk membuat OTP yang aman secara kriptografis
     * Mengikuti rekomendasi audit (Masalah #3)
     */
    public static function generate_secure_otp($digits) {
        try {
            // Metode utama dan paling aman
            if (function_exists('random_int')) {
                $max = pow(10, $digits) - 1;
                $num = random_int(0, $max);
                return str_pad($num, $digits, '0', STR_PAD_LEFT);
            }
        } catch (Exception $e) {
            // Abaikan, lanjut ke fallback
        }

        // Fallback #1: random_bytes (juga aman)
        if (function_exists('random_bytes')) {
            try {
                $bytes = random_bytes(ceil($digits / 2)); // 1 byte = 2 hex chars
                $hex = bin2hex($bytes);
                $num = preg_replace('/[^0-9]/', '', $hex); // Ambil angka saja
                $num = substr($num, 0, $digits); // Potong
                if (strlen($num) < $digits) {
                    // Jika masih kurang, tambahkan dari wp_rand()
                    $num = str_pad($num, $digits, wp_rand(0, 9));
                }
                return $num;
            } catch (Exception $e) {
                // Abaikan, lanjut ke fallback
            }
        }
        
        // Fallback #2: WordPress (aman)
        // Jangan pernah gunakan mt_rand()
        return substr(preg_replace('/[^0-9]/', '', wp_generate_password(20, false)), 0, $digits);
    }
    
    public static function generate_and_send_otp($user_id, $method = 'email') {
        $digits = self::get_setting('otp_digits', 6);
        
        // REVISI: Ganti logika OTP lama
        $otp = self::generate_secure_otp($digits);
        // Akhir Revisi
        
        $expiry_seconds = self::get_setting('otp_validity', 300);
        $expiry_time = time() + $expiry_seconds;

        update_user_meta($user_id, 'sua_otp_code', wp_hash_password($otp));
        update_user_meta($user_id, 'sua_otp_expiry', $expiry_time);

        $sent = false;
        if($method === 'email') {
            $sent = self::send_otp_email($user_id, $otp);
        } elseif ($method === 'whatsapp') {
            $sent = self::send_otp_whatsapp($user_id, $otp);
        }

        if ($sent) {
             update_user_meta($user_id, 'sua_otp_last_sent', time());
        }

        return $sent;
    }

    public static function send_otp_email($user_id, $otp_code) {
        $user = get_userdata($user_id);
        $subject = self::get_setting('otp_email_subject', 'Kode Verifikasi Anda');
        $body = self::get_setting('otp_email_body', 'Kode verifikasi Anda adalah: {otp_code}');
        
        $body = str_replace('{display_name}', $user->display_name, $body);
        $body = str_replace('{otp_code}', $otp_code, $body);

        $headers = ['Content-Type: text/html; charset=UTF-8'];
        return wp_mail($user->user_email, $subject, wpautop($body), $headers);
    }
    
    /**
     * REVISI: Tambahkan fungsi helper baru ini
     * untuk mengirim Email OTP tanpa user_id (untuk alur registrasi)
     */
    public static function send_otp_email_direct($email_to, $display_name, $otp_code) {
        $subject = self::get_setting('otp_email_subject', 'Kode Verifikasi Anda');
        $body = self::get_setting('otp_email_body', 'Kode verifikasi Anda adalah: {otp_code}');
        
        $body = str_replace('{display_name}', $display_name, $body);
        $body = str_replace('{otp_code}', $otp_code, $body);

        $headers = ['Content-Type: text/html; charset=UTF-8'];
        return wp_mail($email_to, $subject, wpautop($body), $headers);
    }
    
    public static function send_otp_whatsapp($user_id, $otp_code) {
        $user = get_userdata($user_id);
        $whatsapp_no = get_user_meta($user_id, 'no_whatsapp', true);

        if(empty($whatsapp_no)) return false;

        return self::send_otp_whatsapp_direct($whatsapp_no, $user->display_name, $otp_code);
    }

    /**
     * REVISI: Fungsi helper baru untuk mengirim WA tanpa user_id
     * Ini akan digunakan oleh alur registrasi
     */
    public static function send_otp_whatsapp_direct($whatsapp_no, $display_name, $otp_code) {
        $endpoint = self::get_setting('waha_api_endpoint');
        $session = self::get_setting('waha_session_name', 'default');
        $api_key = self::get_setting('waha_api_key');
        $template = self::get_setting('waha_message_template', 'Halo {display_name}, kode OTP Anda adalah: {otp_code}');
        $default_country_code = self::get_setting('whatsapp_default_country_code');

        if(empty($endpoint)) {
            self::log_error('WAHA API Endpoint is not configured.');
            self::add_notice('Fitur WhatsApp tidak dikonfigurasi dengan benar oleh administrator.');
            return false;
        }

        $message = str_replace(['{display_name}', '{otp_code}'], [$display_name, $otp_code], $template);
        
        $whatsapp_no = preg_replace('/[^0-9]/', '', $whatsapp_no);

        if (!empty($default_country_code) && substr($whatsapp_no, 0, 1) === '0') {
            $whatsapp_no = $default_country_code . substr($whatsapp_no, 1);
        }

        $request_url = rtrim($endpoint, '/') . '/api/sendText';
        
        $headers = [ 'Content-Type' => 'application/json' ];
        if(!empty($api_key)) {
            $headers['X-Api-Key'] = $api_key;
        }

        $body = json_encode([
            'chatId'  => "{$whatsapp_no}@c.us",
            'text'    => $message,
            'session' => $session,
        ]);

        $response = wp_remote_post($request_url, [
            'method'  => 'POST',
            'headers' => $headers,
            'body'    => $body,
            'timeout' => 20,
        ]);

        if (is_wp_error($response)) {
            $error_message = $response->get_error_message();
            self::log_error('WAHA API WP_Error: ' . $error_message);
            self::add_notice('Gagal terhubung ke layanan WhatsApp. Error: ' . $error_message);
            return false;
        }

        $status_code = wp_remote_retrieve_response_code($response);
        if ($status_code >= 200 && $status_code < 300) {
            return true;
        } else {
            $response_body = wp_remote_retrieve_body($response);
            self::log_error('WAHA API Error: Status ' . $status_code . ' - Body: ' . $response_body);
            self::add_notice('Layanan WhatsApp mengembalikan error. Silakan periksa pengaturan atau coba lagi nanti.');
            return false;
        }
    }
    
    public static function send_welcome_email($user_id) {
        $user = get_userdata($user_id);
        if(empty($user->user_email)) return;

        $subject = self::get_setting('welcome_email_subject', 'Selamat Datang!');
        $body = self::get_setting('welcome_email_body', 'Terima kasih telah mendaftar, {display_name}!');
        
        $body = str_replace('{display_name}', $user->display_name, $body);
        $body = str_replace('{registration_date}', date_i18n(get_option('date_format'), strtotime($user->user_registered)), $body);

        $headers = ['Content-Type: text/html; charset=UTF-8'];
        wp_mail($user->user_email, $subject, wpautop($body), $headers);
    }
    
    public static function get_user_ip() {
        // Hanya percayai REMOTE_ADDR.
        // Header lain seperti HTTP_X_FORWARDED_FOR mudah dipalsukan.
        // Jika situs berada di belakang proxy terpercaya (CloudFlare/NGINX),
        // server HARUS dikonfigurasi untuk mengatur REMOTE_ADDR dengan benar.
        // Plugin tidak boleh mencoba mengurai header yang tidak terpercaya.
        $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        
        // Validasi cepat untuk memastikan itu adalah IP
        if (filter_var($ip, FILTER_VALIDATE_IP)) {
            return $ip;
        }

        return '0.0.0.0';
    }

    public static function verify_recaptcha($token) {
        $secret = self::get_setting('recaptcha_secret_key');
        if (empty($secret) || empty($token)) {
            return false;
        }

        $response = wp_remote_post('https://www.google.com/recaptcha/api/siteverify', [
            'body' => [
                'secret'   => $secret,
                'response' => $token,
                'remoteip' => self::get_user_ip(),
            ],
        ]);
        
        if (is_wp_error($response)) {
            self::log_error('reCAPTCHA verification request failed: ' . $response->get_error_message());
            return false;
        }

        $result = json_decode(wp_remote_retrieve_body($response), true);
        $threshold = (float) self::get_setting('recaptcha_threshold', 0.5);

        if ( !isset($result['success']) || $result['success'] !== true ) {
            $error_codes = isset($result['error-codes']) ? implode(', ', $result['error-codes']) : 'N/A';
            self::log_error("reCAPTCHA check failed. Google reported success=false. Error codes: " . $error_codes);
            return false;
        }
    
        if ( !isset($result['score']) || $result['score'] < $threshold ) {
             self::log_error('reCAPTCHA score (' . ($result['score'] ?? 'N/A') . ') is below the threshold (' . $threshold . ').');
            return false;
        }
    
        return true;
    }

    public static function is_email_domain_allowed($email) {
        $domain = substr(strrchr($email, "@"), 1);
        if (!$domain) {
            return false;
        }
        
        $whitelist_str = self::get_setting('email_whitelist');
        $blacklist_str = self::get_setting('email_blacklist');

        if (!empty($whitelist_str)) {
            $whitelist = array_map('trim', explode(",", $whitelist_str));
            return in_array($domain, $whitelist);
        }

        if (!empty($blacklist_str)) {
            $blacklist = array_map('trim', explode(",", $blacklist_str));
            return !in_array($domain, $blacklist);
        }

        return true;
    }
}
