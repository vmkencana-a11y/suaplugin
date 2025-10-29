<?php
/**
 * File: class-sua-logger.php
 * Menangani semua pencatatan aktivitas ke database kustom.
 */

// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
    die;
}

class SUA_Logger {

    /**
     * Mencatat kejadian ke database.
     *
     * @param string $event_type Tipe kejadian (cth: 'LOGIN_SUCCESS', 'LOGIN_FAILED').
     * @param string $message Deskripsi log.
     * @param int|null $user_id ID pengguna jika ada.
     * @param string|null $ip_address Alamat IP. Jika null, akan diambil otomatis.
     */
    public static function log($event_type, $message, $user_id = null, $ip_address = null) {
        global $wpdb;
        $table_name = $wpdb->prefix . 'sua_logs';

        // Pastikan class helper ada sebelum memanggilnya
        if ( ! class_exists('SUA_Helpers') ) {
             // Muat helper jika belum ada (penting untuk cron)
             require_once SUA_PLUGIN_DIR . 'includes/public/class-sua-helpers.php';
        }
        
        // Jangan log jika tidak ada IP (misalnya dari cron/CLI)
        $ip = $ip_address ?? SUA_Helpers::get_user_ip();
        if (empty($ip) || $ip === '0.0.0.0') {
            return;
        }

        $wpdb->insert(
            $table_name,
            [
                'timestamp'  => current_time('mysql'),
                'event_type' => sanitize_key($event_type),
                'message'    => sanitize_text_field($message),
                'user_id'    => $user_id ? (int) $user_id : null,
                'ip_address' => sanitize_text_field($ip),
            ],
            [
                '%s', // timestamp
                '%s', // event_type
                '%s', // message
                '%d', // user_id
                '%s', // ip_address
            ]
        );
    }
}