<?php
/**
 * File: class-simple-user-access.php
 * Status: VERIFIED & REVISED
 * Revision Note:
 * - This file adds the crucial missing hook to call the `start_session` method.
 * - `add_action('init', $plugin_public, 'start_session', 1)` has been added.
 * - This is the final piece to correctly handle sessions, resolve the "headers already sent" warning, and fix the reCAPTCHA issue.
 *
 * @package    Simple_User_Access
 * @subpackage Simple_User_Access/includes
 * @author     Virtual Media Kencana
 */
class Simple_User_Access {

	protected $loader;
	protected $plugin_name;
	protected $version;

	public function __construct() {
		if ( defined( 'SUA_VERSION' ) ) {
			$this->version = SUA_VERSION;
		} else {
			$this->version = '1.0.0';
		}
		$this->plugin_name = 'simple-user-access';

		$this->load_dependencies();
		$this->define_admin_hooks();
		$this->define_public_hooks();
	}

	private function load_dependencies() {
		require_once plugin_dir_path( dirname( __FILE__ ) ) . 'includes/class-simple-user-access-loader.php';
		require_once plugin_dir_path( dirname( __FILE__ ) ) . 'includes/admin/class-sua-admin.php';
		require_once plugin_dir_path( dirname( __FILE__ ) ) . 'includes/public/class-sua-public.php';
        require_once plugin_dir_path( dirname( __FILE__ ) ) . 'includes/public/class-sua-helpers.php';
		$this->loader = new Simple_User_Access_Loader();
	}

	private function define_admin_hooks() {
		$plugin_admin = new SUA_Admin( $this->get_plugin_name(), $this->get_version() );
		$this->loader->add_action( 'admin_enqueue_scripts', $plugin_admin, 'enqueue_styles_and_scripts' );
		$this->loader->add_action( 'admin_menu', $plugin_admin, 'create_admin_menu' );
        $this->loader->add_action( 'admin_init', $plugin_admin, 'register_settings' );
        
        $this->loader->add_filter( 'manage_users_columns', $plugin_admin, 'add_custom_user_columns' );
        $this->loader->add_action( 'manage_users_custom_column', $plugin_admin, 'render_custom_user_columns', 10, 3 );
        $this->loader->add_filter( 'manage_users_sortable_columns', $plugin_admin, 'add_sortable_user_columns' );
        
        $this->loader->add_action('wp_ajax_sua_update_user_status', $plugin_admin, 'handle_user_status_update');
		$this->loader->add_action('wp_ajax_sua_test_waha', $plugin_admin, 'handle_test_waha');
		$this->loader->add_action('wp_ajax_sua_test_recaptcha', $plugin_admin, 'handle_test_recaptcha');
	}

	private function define_public_hooks() {
		$plugin_public = new SUA_Public( $this->get_plugin_name(), $this->get_version() );
		$this->loader->add_action( 'wp_enqueue_scripts', $plugin_public, 'enqueue_styles_and_scripts' );
        
        // FIX: Add a high-priority action to start the session early and reliably.
        $this->loader->add_action( 'init', $plugin_public, 'start_session', 1 );
        
        $this->loader->add_action( 'init', $plugin_public, 'register_shortcodes');
        $this->loader->add_action( 'init', $plugin_public, 'init_authentication_handler');
        $this->loader->add_action( 'wp_logout', $plugin_public, 'redirect_after_logout');

        // These hooks for redirects are correct and safe.
        $this->loader->add_action( 'init', $plugin_public, 'block_wp_login_page' );
        $this->loader->add_action( 'template_redirect', $plugin_public, 'redirect_logged_in_user_from_auth_pages' );
	}

	public function run() {
		$this->loader->run();
	}

	public function get_plugin_name() {
		return $this->plugin_name;
	}

	public function get_loader() {
		return $this->loader;
	}

	public function get_version() {
		return $this->version;
	}
}
