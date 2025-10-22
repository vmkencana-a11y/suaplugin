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
 * The core plugin class that is used to define internationalization,
 * admin-specific hooks, and public-facing site hooks.
 */
require plugin_dir_path( __FILE__ ) . 'includes/class-simple-user-access.php';

/**
 * Begins execution of the plugin.
 *
 * @since    1.0.0
 */
function run_simple_user_access() {
    $plugin = new Simple_User_Access();
    $plugin->run();
}

run_simple_user_access();
