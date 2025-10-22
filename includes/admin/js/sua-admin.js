jQuery(document).ready(function($) {
    // Handler for when a status toggle switch is changed
    $('.wp-list-table').on('change', '.sua-status-toggle', function() {
        const $switch = $(this);
        const userId = $switch.data('user-id');
        const metaKey = $switch.data('meta-key');
        const onValue = $switch.data('on-value');
        const offValue = $switch.data('off-value');
        
        // Determine the new status based on whether the checkbox is checked
        const newStatus = $switch.is(':checked') ? onValue : offValue;

        // Prepare the data to send via AJAX
        const data = {
            action: 'sua_update_user_status', // The wp_ajax_ hook
            user_id: userId,
            meta_key: metaKey,
            status: newStatus,
            nonce: sua_admin_vars.nonce // The security nonce
        };

        // Send the AJAX request
        $.post(sua_admin_vars.ajax_url, data, function(response) {
            // Remove any old notices first
            $('.sua-admin-notice').remove();
            
            const $notice = $('<div class="sua-admin-notice notice is-dismissible"><p></p></div>');
            
            if (response.success) {
                $notice.addClass('notice-success');
                $notice.find('p').text(response.data.message || 'Status pengguna berhasil diperbarui.');
            } else {
                $notice.addClass('notice-error');
                $notice.find('p').text('Gagal memperbarui status: ' + (response.data.message || 'Error tidak diketahui.'));
                // Revert the switch to its previous state on failure
                $switch.prop('checked', !$switch.prop('checked'));
            }
            
            // Display the notice at the top of the user list
            $('.wrap h1').after($notice);

            // Automatically remove the notice after 5 seconds
            setTimeout(function() {
                $notice.fadeOut('slow', function() {
                    $(this).remove();
                });
            }, 5000);

        }).fail(function() {
            // Handle cases where the AJAX request itself fails
            $('.sua-admin-notice').remove();
            const $errorNotice = $('<div class="sua-admin-notice notice notice-error is-dismissible"><p>Terjadi kesalahan saat menghubungi server. Silakan coba lagi.</p></div>');
            $('.wrap h1').after($errorNotice);
            $switch.prop('checked', !$switch.prop('checked')); // Revert on failure
        });
    });
});


