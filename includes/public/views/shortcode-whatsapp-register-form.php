<?php
/**
 * View for the WhatsApp Register Form shortcode.
 *
 * @package    Simple_User_Access
 * @subpackage Simple_User_Access/public/views
 */
?>
<div class="sua-form-container">
    <h2>Daftar dengan WhatsApp</h2>

    <?php SUA_Helpers::display_notices(); ?>

    <form id="sua-wa-register-form" class="sua-form" action="" method="post">
        <div class="sua-form-field">
            <label for="sua_first_name">Nama Depan</label>
            <input type="text" id="sua_first_name" name="sua_first_name" required>
        </div>

        <div class="sua-form-field">
            <label for="sua_last_name">Nama Belakang</label>
            <input type="text" id="sua_last_name" name="sua_last_name" required>
        </div>

        <div class="sua-form-field">
            <label for="sua_whatsapp">No. WhatsApp</label>
            <input type="tel" id="sua_whatsapp" name="sua_whatsapp" required>
        </div>

        <div class="sua-form-field-checkbox">
            <input type="checkbox" id="sua-tos" name="sua_tos" required>
            <label for="sua-tos">Saya Menerima Syarat & Ketentuan</label>
        </div>

        <?php if (SUA_Helpers::get_setting('whatsapp_enable_recaptcha')) : ?>
            <input type="hidden" name="recaptcha_token" class="recaptcha_token">
        <?php endif; ?>

        <?php if (SUA_Helpers::get_setting('whatsapp_enable_nonce')) { 
            wp_nonce_field('sua_whatsapp_register_action', 'sua_whatsapp_register_nonce'); 
        } ?>

        <input type="hidden" name="sua_action" value="whatsapp_register">

        <div class="sua-form-submit">
            <button type="submit" class="sua-submit-button">Daftar</button>
        </div>
    </form>
</div>
