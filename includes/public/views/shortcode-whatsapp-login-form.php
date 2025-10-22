<?php
/**
 * View for the WhatsApp Login Form shortcode.
 *
 * @package    Simple_User_Access
 * @subpackage Simple_User_Access/public/views
 */
?>
<div class="sua-form-container">
    <h2>Masuk dengan WhatsApp</h2>

    <?php SUA_Helpers::display_notices(); ?>

    <form id="sua-wa-login-form" class="sua-form" action="" method="post">
        <div class="sua-form-field">
            <label for="sua_whatsapp">No. WhatsApp</label>
            <input type="tel" id="sua_whatsapp" name="sua_whatsapp" required>
        </div>
        
        <?php if (SUA_Helpers::get_setting('whatsapp_enable_recaptcha')) : ?>
            <input type="hidden" name="recaptcha_token" class="recaptcha_token">
        <?php endif; ?>

        <?php if (SUA_Helpers::get_setting('whatsapp_enable_nonce')) { 
            wp_nonce_field('sua_whatsapp_login_action', 'sua_whatsapp_login_nonce'); 
        } ?>

        <input type="hidden" name="sua_action" value="whatsapp_login">

        <div class="sua-form-submit">
            <button type="submit" class="sua-submit-button">Kirim Kode Verifikasi</button>
        </div>
    </form>
</div>
