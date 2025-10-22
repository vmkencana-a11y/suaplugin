<?php
/**
 * View for the OTP Verification Form shortcode.
 *
 * @package    Simple_User_Access
 * @subpackage Simple_User_Access/public/views
 */

$wait_time = SUA_Helpers::get_setting('otp_resend_wait', 60);
// Get the dynamic digit count from settings
$otp_digits = SUA_Helpers::get_setting('otp_digits', 6);
?>
<div class="sua-form-container">
    <h2>Verifikasi Kode OTP</h2>

    <?php SUA_Helpers::display_notices(); ?>

    <p style="text-align: center; margin-bottom: 1.5em; color: #555;">Kami telah mengirimkan kode verifikasi. Silakan periksa dan masukkan di bawah ini.</p>

    <form id="sua-otp-form" class="sua-form" action="" method="post">
        <div class="sua-form-field">
            <label for="sua_otp_code">Masukan Kode OTP</label>
            <input type="text" id="sua_otp_code" name="sua_otp_code" required maxlength="<?php echo esc_attr($otp_digits); ?>" pattern="\d{<?php echo esc_attr($otp_digits); ?>}">
        </div>
        
        <?php 
        // FIX: Add nonce field for security
        wp_nonce_field('sua_otp_verify_action', 'sua_otp_verify_nonce'); 
        ?>
        <input type="hidden" name="sua_action" value="otp_verify">

        <div class="sua-form-submit">
            <button type="submit" class="sua-submit-button">Validasi</button>
        </div>
    </form>

    <div id="sua-resend-otp-container" data-wait-time="<?php echo esc_attr($wait_time); ?>" style="text-align: center; margin-top: 1.5em;">
        <button type="button" id="sua-resend-otp-button">Kirim Ulang Kode</button>
        <span id="sua-otp-countdown"></span>
    </div>
</div>
