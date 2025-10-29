<?php
/**
 * Plugin Name:       Simple User Access
 * Plugin URI:        https://example.com/
 * Description:       A custom plugin to replace the default WordPress login and registration system with custom pages and authentication methods.
 * Version:           1.1.0
 * Author:            Virtual Media Kencana
 * Author URI:        https://example.com/
 * License:           GPL v2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       simple-user-access
 * Domain Path:       /languages
 */

// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
    die;
}

/**
 * Define constants for the plugin.
 */
define( 'SUA_VERSION', '1.1.0' );
define( 'SUA_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'SUA_PLUGIN_URL', plugin_dir_url( __FILE__ ) );

/**
 * Memuat file dependensi inti.
 */
require plugin_dir_path( __FILE__ ) . 'includes/class-sua-logger.php';
require plugin_dir_path( __FILE__ ) . 'includes/class-simple-user-access.php';

/**
 * Fungsi aktivasi: Hanya berjalan saat plugin diaktifkan.
 * Aman, tidak ada output.
 */
function sua_plugin_activation() {
    global $wpdb;
    $table_name = $wpdb->prefix . 'sua_logs';
    $charset_collate = $wpdb->get_charset_collate();

    // PERBAIKAN: Mengganti 'INDEX' dengan 'KEY' dan memberi nama unik 
    // untuk setiap index agar kompatibel dengan dbDelta.
    $sql = "CREATE TABLE $table_name (
        log_id BIGINT(20) NOT NULL AUTO_INCREMENT,
        timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        event_type VARCHAR(50) NOT NULL,
        message TEXT NOT NULL,
        user_id BIGINT(20) UNSIGNED DEFAULT NULL,
        ip_address VARCHAR(100) DEFAULT NULL,
        PRIMARY KEY (log_id),
        KEY idx_event_type (event_type),
        KEY idx_user_id (user_id),
        KEY idx_ip_address (ip_address)
    ) $charset_collate;";

    require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
    dbDelta($sql);
    
    // Jadwalkan cron harian jika belum ada
    if (!wp_next_scheduled('sua_purge_old_logs_hook')) {
        wp_schedule_event(time(), 'daily', 'sua_purge_old_logs_hook');
    }
}
register_activation_hook(__FILE__, 'sua_plugin_activation');

/**
 * Fungsi deaktivasi: Membersihkan cron.
 */
function sua_plugin_deactivation() {
    wp_clear_scheduled_hook('sua_purge_old_logs_hook');
}
register_deactivation_hook(__FILE__, 'sua_plugin_deactivation');

/**
 * Menghapus tabel log kustom saat plugin di-uninstall.
 */
function sua_plugin_uninstall() {
    global $wpdb;
    $table_name = $wpdb->prefix . 'sua_logs';
    $wpdb->query("DROP TABLE IF EXISTS $table_name");
}
register_uninstall_hook(__FILE__, 'sua_plugin_uninstall');

/**
 * Fungsi yang dijalankan oleh cron untuk membersihkan log lama.
 */
function sua_run_log_purger() {
    global $wpdb;
    $table_name = $wpdb->prefix . 'sua_logs';
    
    $retention_days = apply_filters('sua_log_retention_days', 30); 
    
    $wpdb->query(
        $wpdb->prepare(
            "DELETE FROM $table_name WHERE timestamp < NOW() - INTERVAL %d DAY",
            $retention_days
        )
    );
}

/**
 * Fungsi inti yang menjalankan plugin.
 *
 * @since    1.0.0
 */
function run_simple_user_access() {
    $plugin = new Simple_User_Access();
    $plugin->run();

    // REVISI: Daftarkan hook cron di sini, BUKAN di scope global
    add_action('sua_purge_old_logs_hook', 'sua_run_log_purger');
}

/**
 * Mulai plugin.
 * REVISI: Menggunakan 'plugins_loaded' untuk mencegah "unexpected output" saat aktivasi.
 */
add_action( 'plugins_loaded', 'run_simple_user_access' );

// REVISI: Kurung kurawal '}' ekstra yang ada di akhir file Anda telah dihapus.