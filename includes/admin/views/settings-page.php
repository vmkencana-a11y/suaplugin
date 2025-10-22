<div class="wrap">
    <h1>Simple User Access Settings</h1>

    <?php
    settings_errors();
    ?>

    <form method="post" action="options.php">
        <?php
        settings_fields('sua_settings_group');
        
        // REVISION: Add a hidden field to explicitly pass the current page slug.
        echo '<input type="hidden" name="sua_current_page_slug" value="' . esc_attr($current_page_slug) . '" />';
        
        do_settings_sections($current_page_slug);
        
        submit_button('Simpan Perubahan');
        ?>
    </form>
</div>
