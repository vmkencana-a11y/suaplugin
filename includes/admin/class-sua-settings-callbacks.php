<?php
/**
 * File: class-sua-settings-callbacks.php
 * Status: VERIFIED & REVISED
 * Revision Note:
 * - This file adds a new callback method: `display_readonly_text_callback`.
 * - This new method is used to render the non-editable Google Callback URL field on the settings page.
 * - No other functionality in this file has been altered.
 *
 * @package    Simple_User_Access
 * @subpackage Simple_User_Access/admin
 */
class SUA_Settings_Callbacks {

    private $options;

    public function __construct() {
        $this->options = get_option('sua_settings');
    }

    public function text_callback($args) {
        $name = esc_attr($args['name']);
        $value = isset($this->options[$name]) ? esc_attr($this->options[$name]) : '';
        $type = isset($args['type']) ? esc_attr($args['type']) : 'text';
        $step = isset($args['step']) ? "step='{$args['step']}'" : '';
        $min = isset($args['min']) ? "min='{$args['min']}'" : '';
        $max = isset($args['max']) ? "max='{$args['max']}'" : '';
        printf('<input type="%s" id="%s" name="sua_settings[%s]" value="%s" class="regular-text" %s %s %s />', $type, $name, $name, $value, $step, $min, $max);
        if (isset($args['description'])) {
            echo '<p class="description">' . wp_kses_post($args['description']) . '</p>';
        }
    }

    public function password_callback($args) {
        $name = esc_attr($args['name']);
        $value = isset($this->options[$name]) ? esc_attr($this->options[$name]) : '';
        printf('<input type="password" id="%s" name="sua_settings[%s]" value="%s" class="regular-text" />', $name, $name, $value);
    }

    public function textarea_callback($args) {
        $name = esc_attr($args['name']);
        $value = isset($this->options[$name]) ? esc_textarea($this->options[$name]) : '';
        printf('<textarea id="%s" name="sua_settings[%s]" rows="5" class="large-text">%s</textarea>', $name, $name, $value);
        if (isset($args['description'])) {
            echo '<p class="description">' . wp_kses_post($args['description']) . '</p>';
        }
    }

    public function toggle_switch_callback($args) {
        $name = esc_attr($args['name']);
        $checked = !empty($this->options[$name]) ? 'checked' : '';
        echo "<label class='sua-switch'><input type='checkbox' id='{$name}' name='sua_settings[{$name}]' value='1' {$checked}><span class='sua-slider sua-round'></span></label>";
    }

    public function page_select_callback($args) {
        $name = esc_attr($args['name']);
        $selected_page = isset($this->options[$name]) ? intval($this->options[$name]) : 0;
        wp_dropdown_pages([
            'name'             => "sua_settings[{$name}]",
            'selected'         => $selected_page,
            'show_option_none' => '— Pilih Halaman —',
            'option_none_value'=> '0',
        ]);
        if (isset($args['description'])) {
            echo '<p class="description">' . wp_kses_post($args['description']) . '</p>';
        }
    }

    public function wp_editor_callback($args) {
        $name = esc_attr($args['name']);
        $content = isset($this->options[$name]) ? $this->options[$name] : '';
        wp_editor($content, $name, ['textarea_name' => "sua_settings[{$name}]"]);
        
        if ($name === 'welcome_email_body') {
            echo '<p class="description">Placeholder yang tersedia: <code>{display_name}</code>, <code>{registration_date}</code></p>';
        } elseif ($name === 'otp_email_body') {
            echo '<p class="description">Placeholder yang tersedia: <code>{display_name}</code>, <code>{otp_code}</code></p>';
        }
    }

    public function shortcode_display_callback($args) {
        $shortcode = esc_attr($args['shortcode']);
        echo "<input type='text' class='regular-text' value='{$shortcode}' readonly onfocus='this.select();' />";
    }

    /**
     * REVISION: New callback to display a read-only text field, used for the Google Callback URL.
     */
    public function display_readonly_text_callback($args) {
        $value = esc_attr($args['value']);
        echo "<input type='text' class='regular-text' value='{$value}' readonly onfocus='this.select();' />";
        if (isset($args['description'])) {
            echo '<p class="description">' . wp_kses_post($args['description']) . '</p>';
        }
    }
    public function recaptcha_test_button_callback() {
    echo '<button type="button" id="sua-test-recaptcha-btn" class="button">Jalankan Tes Verifikasi Secret Key</button>';
    echo '<p class="description">Ini akan memeriksa apakah Secret Key Anda valid dengan mengirim permintaan tes ke Google.</p>';
    echo '<span id="sua-recaptcha-test-status" style="margin-left: 10px;"></span>';
    }

    public function waha_test_button_callback() {
    echo '<input type="tel" id="sua-waha-test-number" placeholder="Contoh: 628123456789" class="regular-text" style="width: 200px; margin-right: 10px;">';
    echo '<button type="button" id="sua-test-waha-btn" class="button">Kirim Pesan Tes</button>';
    echo '<p class="description">Masukkan nomor WA lengkap (dengan kode negara) untuk mengirim pesan tes. Pastikan pengaturan WAHA di atas sudah disimpan.</p>';
    echo '<span id="sua-waha-test-status" style="margin-left: 10px;"></span>';
    }
}
