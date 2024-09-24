jQuery(document).ready(function($) {
    $('#wordpresscopilot-minimize-chat').on('click', function() {
        $('#wordpresscopilot-chat-popup').toggleClass('minimized');
        $(this).text(function(i, text) {
            return text === "-" ? "+" : "-";
        });
    });
});