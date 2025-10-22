<?php
/**
 * View for the Email Login Form shortcode.
 *
 * @package    Simple_User_Access
 * @subpackage Simple_User_Access/public/views
 */
?>
<div class="sua-form-container">
    <h2>Masuk dengan Email</h2>

    <?php SUA_Helpers::display_notices(); ?>

    <form id="sua-email-login-form" class="sua-form" action="" method="post">
        <div class="sua-form-field">
            <label for="sua_email">Alamat Email</label>
            <input type="email" id="sua_email" name="sua_email" required>
        </div>
        
        <?php if (SUA_Helpers::get_setting('email_enable_recaptcha')) : ?>
            <input type="hidden" name="recaptcha_token" class="recaptcha_token">
        <?php endif; ?>

        <?php if (SUA_Helpers::get_setting('email_enable_nonce')) { 
            wp_nonce_field('sua_email_login_action', 'sua_email_login_nonce'); 
        } ?>

        <input type="hidden" name="sua_action" value="email_login">

        <div class="sua-form-submit">
            <button type="submit" class="sua-submit-button">Kirim Kode Verifikasi</button>
        </div>
    </form>
</div>
