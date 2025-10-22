/**
 * File: sua-public.js
 * Status: VERIFIED & REVISED
 * Revision Note: 
 * - This file restores the correct logic for retrieving the reCAPTCHA site key.
 * - The previous revision mistakenly included PHP code, which is now fixed.
 * - The code now correctly reads the site key from `sua_public_vars.recaptcha_site_key`, which is passed from PHP via wp_localize_script.
 * - No other functionality in this file has been altered.
 */
jQuery(document).ready(function($) {

    // --- Terms of Service Checkbox Handler ---
    const $tosCheckbox = $('#sua-tos');
    const $submitButton = $('.sua-submit-button');

    if ($tosCheckbox.length && $submitButton.length) {
        if ($tosCheckbox.is(':visible')) {
            $submitButton.prop('disabled', !$tosCheckbox.is(':checked'));
        }
        $tosCheckbox.on('change', function() {
            $submitButton.prop('disabled', !$(this).is(':checked'));
        });
    }

    // --- OTP Countdown Timer & AJAX Resend ---
    const $resendContainer = $('#sua-resend-otp-container');
    if ($resendContainer.length) {
        const $resendButton = $('#sua-resend-otp-button');
        const $countdownSpan = $('#sua-otp-countdown');
        let countdownTime = parseInt($resendContainer.data('wait-time'), 10) || 60;

        function startCountdown() {
            $resendButton.prop('disabled', true);
            $countdownSpan.show();
            
            let timer = countdownTime;
            const interval = setInterval(function() {
                const minutes = Math.floor(timer / 60);
                const seconds = timer % 60;
                $countdownSpan.text('(Tunggu ' + minutes + ':' + (seconds < 10 ? '0' : '') + seconds + ')');
                
                if (--timer < 0) {
                    clearInterval(interval);
                    $resendButton.prop('disabled', false);
                    $countdownSpan.hide();
                }
            }, 1000);
        }

        startCountdown();

        $resendButton.on('click', function(e) {
            e.preventDefault();
            
            const data = {
                action: 'sua_resend_otp',
                nonce: sua_public_vars.resend_otp_nonce
            };

            $resendButton.prop('disabled', true);

            $.post(sua_public_vars.ajax_url, data, function(response) {
                $('.sua-form-container > .sua-notice').remove();
                
                const $notice = $('<div class="sua-notice"><p></p></div>');
                const message = response.data.message || 'Terjadi kesalahan.';
                $notice.find('p').text(message);

                if (response.success) {
                    $notice.addClass('sua-notice-success');
                    startCountdown();
                } else {
                    $notice.addClass('sua-notice-error');
                    $resendButton.prop('disabled', false);
                }
                
                $('.sua-form-container').prepend($notice);
                
            }).fail(function() {
                $('.sua-form-container > .sua-notice').remove();
                const $notice = $('<div class="sua-notice sua-notice-error"><p>Gagal terhubung ke server. Silakan coba lagi.</p></div>');
                $('.sua-form-container').prepend($notice);
                $resendButton.prop('disabled', false);
            });
        });
    }

    // --- reCAPTCHA v3 Handler ---
    const recaptchaSiteKey = sua_public_vars.recaptcha_site_key;
    
    if (recaptchaSiteKey && typeof grecaptcha !== 'undefined') {
        $('.sua-form').on('submit', function(e) {
            const $form = $(this);
            if ($form.find('.recaptcha_token').length > 0) {
                e.preventDefault();
                
                grecaptcha.ready(function() {
                    grecaptcha.execute(recaptchaSiteKey, { action: 'submit' }).then(function(token) {
                        $form.find('.recaptcha_token').val(token);
                        $form.off('submit').submit();
                    });
                });
            }
        });
    }
});
