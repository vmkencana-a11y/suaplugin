<?php
/**
 * View for the Google Button shortcode.
 *
 * @package    Simple_User_Access
 * @subpackage Simple_User_Access/public/views
 */
?>
<div class="sua-google-button-container">
     <div class="sua-separator">Atau</div>
    <a href="<?php echo esc_url( home_url('/?sua-action=google_login') ); ?>" class="sua-google-button">
        <img src="https://www.google.com/favicon.ico" alt="Google icon">
        Daftar/Masuk dengan Google
    </a>
</div>
