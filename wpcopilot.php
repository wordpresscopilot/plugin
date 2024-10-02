<?php
/**
 * Plugin Name: WPCopilot  
 * Description: AI-Powered Wordpress Development
 * Version: 0.0.9
 * Author: WPCopilot - wpc.dev
 * Author URI: https://wpc.dev
 * License URI: http://www.gnu.org/licenses/gpl-2.0.txt
 * Text Domain: wpcopilot
 * Domain Path: /languages
 */

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

class WPCopilot_Options_Access {
    private $api_key;
    private $api_key_status;
    private $plugin_version;

    public function __construct() {
        $this->api_key = get_option('wpcopilot_api_key', $this->generate_default_api_key());
        $this->api_key_status = $this->check_api_key_status();
        $this->plugin_version = '0.0.9';
        add_action('rest_api_init', array($this, 'register_api_endpoints'));
        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_action('admin_init', array($this, 'register_settings'));
        add_filter('plugin_action_links_' . plugin_basename(__FILE__), array($this, 'add_settings_link'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_scripts'));
        // add_action('admin_footer', array($this, 'add_chat_popup'));
        add_action('wp_ajax_auto_login', array($this, 'auto_login'));
        add_action('wp_ajax_nopriv_auto_login', array($this, 'auto_login'));

        add_filter('x_frame_options', array($this, 'allow_iframe_from_specific_domains'));
        add_filter('content_security_policy', array($this, 'allow_iframe_from_specific_domains'));
        add_action('send_headers', array($this, 'modify_headers'), 1);
        add_action('admin_init', array($this, 'allow_iframe_in_admin'));
    }

    private function generate_default_api_key() {
        if (function_exists('wp_generate_uuid4')) {
            return wp_generate_uuid4();
        } else {
            // Fallback method if wp_generate_uuid4 is not available
            return sprintf('%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
                mt_rand(0, 0xffff), mt_rand(0, 0xffff),
                mt_rand(0, 0xffff),
                mt_rand(0, 0x0fff) | 0x4000,
                mt_rand(0, 0x3fff) | 0x8000,
                mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff)
            );
        }
    }

    public function allow_iframe_in_admin() {
        $allowed_domains = array('localhost', 'localhost:3000', 'wpc.dev', 'dev.wpc.dev', 'app.wpc.dev');
        $origin = isset($_SERVER['HTTP_ORIGIN']) ? $_SERVER['HTTP_ORIGIN'] : '';
        $parsed_origin = parse_url($origin);
        
        if (isset($parsed_origin['host']) && in_array($parsed_origin['host'], $allowed_domains)) {
            // Remove X-Frame-Options header
            header_remove('X-Frame-Options');
            
            // Set Content-Security-Policy header
            header("Content-Security-Policy: frame-ancestors 'self' " . esc_url($origin));
        }
    }
    public function modify_headers() {
        $allowed_domains = array('localhost', 'localhost:3000', 'wpc.dev', 'dev.wpc.dev', 'app.wpc.dev');
        $origin = isset($_SERVER['HTTP_ORIGIN']) ? $_SERVER['HTTP_ORIGIN'] : '';
        $parsed_origin = parse_url($origin);
        
        if (isset($parsed_origin['host']) && in_array($parsed_origin['host'], $allowed_domains)) {
            // Remove X-Frame-Options header
            header_remove('X-Frame-Options');
            
            // Set Content-Security-Policy header
            header("Content-Security-Policy: frame-ancestors 'self' " . esc_url($origin));
        }
    }

    public function allow_iframe_from_specific_domains($header) {
        $allowed_domains = array('localhost', 'localhost:3000', 'wpc.dev', 'dev.wpc.dev', 'app.wpc.dev', 'agent-sandbox-1.local');
        $origin = isset($_SERVER['HTTP_ORIGIN']) ? $_SERVER['HTTP_ORIGIN'] : '';
        $parsed_origin = parse_url($origin);
        
        if (isset($parsed_origin['host']) && in_array($parsed_origin['host'], $allowed_domains)) {
            // Remove existing X-Frame-Options header
            header_remove('X-Frame-Options');
            
            // Set Content-Security-Policy header
            header("Content-Security-Policy: frame-ancestors 'self' " . esc_url($origin));
            
            // Set X-Frame-Options for older browsers
            return "ALLOW-FROM " . esc_url($origin);
        }
        
        return $header;
    }

    private function check_api_key_status() {
        // Implement your API key validation logic here
        // For example, you could make a request to your API to check if the key is valid
        // Return true if the key is valid, false otherwise
        return true; // Placeholder return value
    }

    public function register_api_endpoints() {
        register_rest_route('wpcopilot/v1', '/site-info', array(
            'methods' => 'GET',
            'callback' => array($this, 'get_site_info'),
            'permission_callback' => array($this, 'check_permission')
        ));
        register_rest_route('wpcopilot/v1', '/plugins', array(
            'methods' => 'GET',
            'callback' => array($this, 'get_plugin_info'),
            'permission_callback' => array($this, 'check_permission')
        ));

        register_rest_route('wpcopilot/v1', '/health', array(
            'methods' => 'GET',
            'callback' => array($this, 'get_health_check'),
            'permission_callback' => '__return_true'
        ));

        register_rest_route('wpcopilot/v1', '/run-sql', array(
            'methods' => 'POST',
            'callback' => array($this, 'run_sql_query'),
            'permission_callback' => array($this, 'check_permission')
        ));

        register_rest_route('wpcopilot/v1', '/run-php', array(
            'methods' => 'POST',
            'callback' => array($this, 'run_php_code'),
            'permission_callback' => array($this, 'check_permission')
        ));

        register_rest_route('wpcopilot/v1', '/run-wp-cli', array(
            'methods' => 'POST',
            'callback' => array($this, 'run_wp_cli_command'),
            'permission_callback' => array($this, 'check_permission')
        ));

        register_rest_route('wpcopilot/v1', '/upload-media', array(
            'methods' => 'POST',
            'callback' => array($this, 'upload_media_by_url'),
            'permission_callback' => array($this, 'check_permission')
        ));

        register_rest_route('wpcopilot/v1', '/flush-cache', array(
            'methods' => 'POST',
            'callback' => array($this, 'flush_cache'),
            'permission_callback' => array($this, 'check_permission')
        ));

        register_rest_route('wpcopilot/v1', '/install-plugin', array(
            'methods' => 'POST',
            'callback' => array($this, 'install_plugin_endpoint'),
            'permission_callback' => array($this, 'check_permission')
        ));
        register_rest_route('wpcopilot/v1', '/install-plugin-file', array(
            'methods' => 'POST',
            'callback' => array($this, 'install_plugin_file_endpoint'),
            'permission_callback' => array($this, 'check_permission')
        ));

        register_rest_route('wpcopilot/v1', '/get-admin-login-link', array(
            'methods' => 'GET',
            'callback' => array($this, 'get_admin_login_link'),
            'permission_callback' => array($this, 'check_permission')
        ));
        register_rest_route('wpcopilot/v1', '/check-login-status', array(
            'methods' => 'GET',
            'callback' => array($this, 'check_login_status'),
            'permission_callback' => '__return_true'
        ));

        register_rest_route('wpcopilot/v1', '/remove-plugin', array(
            'methods' => 'POST',
            'callback' => array($this, 'remove_plugin_endpoint'),
            'permission_callback' => array($this, 'check_permission')
        ));
    }

    public function check_login_status() {
        $current_user = wp_get_current_user();
        $is_logged_in = is_user_logged_in();
    
        $response = array(
            'is_logged_in' => $is_logged_in,
            'user_info' => array(
                'id' => $current_user->ID,
                'username' => $current_user->user_login,
                'email' => $current_user->user_email,
                'roles' => $current_user->roles,
            ),
        );
    
        return new WP_REST_Response($response, 200);
    }

    public function check_permission($request) {
        $provided_key = $request->get_header('Authorization');
        if (!empty($provided_key)) {
            // Check if it's a Bearer token
            if (preg_match('/^Bearer\s+(.*)$/i', $provided_key, $matches)) {
                $provided_key = $matches[1];
            }
        } else {
            // If not in header, check for api_key parameter
            $provided_key = $request->get_param('api_key');
        }
        
        if ($provided_key === $this->api_key) {
            return true;
        }
        return new WP_Error('rest_forbidden', esc_html__('Invalid API Key', 'wpcopilot'), array('status' => 403));
    }

    public function flush_cache($request) {
        if (!current_user_can('install_plugins')) {
            return new WP_Error('rest_forbidden', esc_html__('You do not have permission to install plugins.', 'wpcopilot'), array('status' => 403));
        }

        $params = $request->get_json_params();
        // Flush transients
        if (function_exists('wp_clear_scheduled_hook')) {
            wp_clear_scheduled_hook('delete_expired_transients');
        }
        delete_expired_transients(true);

        // Flush rewrite rules
        flush_rewrite_rules();

        // Flush cache for popular caching plugins
        // W3 Total Cache
        if (function_exists('w3tc_flush_all')) {
            w3tc_flush_all();
        }

        // WP Super Cache
        if (function_exists('wp_cache_clear_cache')) {
            wp_cache_clear_cache();
        }

        // WP Rocket
        if (function_exists('rocket_clean_domain')) {
            rocket_clean_domain();
        }

        // WP Fastest Cache
        if (function_exists('wpfc_clear_all_cache')) {
            wpfc_clear_all_cache(true);
        }

        // LiteSpeed Cache
        if (class_exists('LiteSpeed_Cache_API') && method_exists('LiteSpeed_Cache_API', 'purge_all')) {
            LiteSpeed_Cache_API::purge_all();
        }

        // Autoptimize
        if (class_exists('autoptimizeCache') && method_exists('autoptimizeCache', 'clearall')) {
            autoptimizeCache::clearall();
        }

        // WP-Optimize
        if (function_exists('wpo_cache_flush')) {
            wpo_cache_flush();
        }

        // Comet Cache
        if (class_exists('comet_cache') && method_exists('comet_cache', 'clear')) {
            comet_cache::clear();
        }

        // Cache Enabler
        if (class_exists('Cache_Enabler') && method_exists('Cache_Enabler', 'clear_total_cache')) {
            Cache_Enabler::clear_total_cache();
        }

        // Hummingbird
        if (class_exists('\Hummingbird\Core\Utils') && method_exists('\Hummingbird\Core\Utils', 'flush_cache')) {
            \Hummingbird\Core\Utils::flush_cache();
        }

        // Swift Performance
        if (class_exists('Swift_Performance_Cache') && method_exists('Swift_Performance_Cache', 'clear_all_cache')) {
            Swift_Performance_Cache::clear_all_cache();
        }

        // WP Optimize
        if (class_exists('WP_Optimize') && method_exists('WP_Optimize', 'get_page_cache') && method_exists('WP_Optimize', 'get_minify')) {
            WP_Optimize()->get_page_cache()->purge();
            WP_Optimize()->get_minify()->purge();
        }

        // SG Optimizer
        if (function_exists('sg_cachepress_purge_cache')) {
            sg_cachepress_purge_cache();
        }

        // Breeze
        if (class_exists('Breeze_Admin') && method_exists('Breeze_Admin', 'breeze_clear_all_cache')) {
            Breeze_Admin::breeze_clear_all_cache();
        }

        return new WP_REST_Response(array('message' => 'Cache flushed successfully'), 200);
    }

    public function get_site_info() {
        $response = array(
            'agent_name' => 'WPCopilot',
            'plugin_version' => $this->plugin_version,
            'general_info' => $this->get_general_info(),
            'theme_info' => $this->get_theme_info(),
            // 'posts' => $this->get_wordpress_posts(),
            // 'menus' => $this->get_menu_info(),
            // 'favicon' => $this->get_favicon(),
            // 'widgets' => $this->get_widget_info(),
            'site_logo' => $this->get_site_logo(),
        );
        return new WP_REST_Response($response, 200);
    }

    public function get_health_check($request) {
        $response = array(
            'status' => 'ok',
            'message' => esc_html__('WPCopilot API is functioning correctly', 'wpcopilot'),
            'timestamp' => current_time('mysql'),
            'plugin_version' => $this->plugin_version
        );

        $provided_key = $request->get_header('Authorization');
        if (!empty($provided_key)) {
            // Check if it's a Bearer token
            if (preg_match('/^Bearer\s+(.*)$/i', $provided_key, $matches)) {
                $provided_key = $matches[1];
            }
        } else {
            // If not in header, check for api_key parameter
            $provided_key = $request->get_param('api_key');
        }

        if (!empty($provided_key)) {
            $response['api_key_valid'] = $provided_key === $this->api_key;
        }

        return new WP_REST_Response($response, 200);
    }

    public function run_sql_query($request) {
        global $wpdb;

        $params = $request->get_json_params();
        $query = isset($params['query']) ? sanitize_text_field($params['query']) : '';

        if (empty($query)) {
            return new WP_Error('invalid_query', esc_html__('SQL query is required', 'wpcopilot'), array('status' => 400));
        }
        // $allowed_operations = array('SELECT', 'SHOW', 'DESCRIBE', 'DESC');
        // $operation = strtoupper(substr(trim($query), 0, 6));
        
        // if (!in_array($operation, $allowed_operations, true)) {
        //     return new WP_Error('forbidden_operation', esc_html__('Only SELECT, SHOW, DESCRIBE, and DESC operations are allowed', 'wpcopilot'), array('status' => 403));
        // }

        $results = $wpdb->get_results($query, ARRAY_A);

        if ($results === null) {
            return new WP_Error('query_error', esc_html($wpdb->last_error), array('status' => 500));
        }

        return new WP_REST_Response($results, 200);
    }

    public function run_php_code($request) {
        $params = $request->get_json_params();
        $code = isset($params['code']) ? sanitize_text_field($params['code']) : '';

        if (empty($code)) {
            return new WP_Error('invalid_code', esc_html__('PHP code is required', 'wpcopilot'), array('status' => 400));
        }

        // Execute the PHP code
        ob_start();
        $return_value = eval($code);
        $output = ob_get_clean();

        $response = array(
            'output' => esc_html($output),
            'return_value' => esc_html($return_value)
        );

        return new WP_REST_Response($response, 200);
    }

    public function run_wp_cli_command($request) {
        $params = $request->get_json_params();
        $command = isset($params['command']) ? sanitize_text_field($params['command']) : '';

        if (empty($command)) {
            return new WP_Error('invalid_command', esc_html__('WP-CLI command is required', 'wpcopilot'), array('status' => 400));
        }

        // Check if WP-CLI is available
        if (class_exists('WP_CLI')) {
            // Execute the WP-CLI command using WP_CLI class
            ob_start();
            WP_CLI::run_command(explode(' ', $command));
            $output = ob_get_clean();
        } else {
            // Path to WP-CLI
            $wp_cli_path = '/usr/local/bin/wp';

            // Check if WP-CLI is available at the specified path
            if (!file_exists($wp_cli_path)) {
                return new WP_Error('wp_cli_not_available', esc_html__('WP-CLI is not available', 'wpcopilot'), array('status' => 500));
            }

            // Execute the WP-CLI command using shell
            $full_command = escapeshellcmd($wp_cli_path . ' ' . $command);
            $process = proc_open($full_command, [
                1 => ['pipe', 'w'],
                2 => ['pipe', 'w']
            ], $pipes);

            if (!is_resource($process)) {
                return new WP_Error('command_execution_failed', esc_html__('Failed to execute WP-CLI command', 'wpcopilot'), array('status' => 500));
            }

            $output = stream_get_contents($pipes[1]);
            $error_output = stream_get_contents($pipes[2]);

            fclose($pipes[1]);
            fclose($pipes[2]);

            $return_code = proc_close($process);

            if ($return_code !== 0) {
                return new WP_Error('command_execution_failed', esc_html($error_output), array('status' => 500));
            }
        }

        $response = array(
            'output' => esc_html($output)
        );

        return new WP_REST_Response($response, 200);
    }

    public function upload_media_by_url($request) {
        $params = $request->get_json_params();
        $url = isset($params['url']) ? esc_url_raw($params['url']) : '';
        $filename = isset($params['filename']) ? sanitize_file_name($params['filename']) : '';

        if (empty($url)) {
            return new WP_Error('invalid_url', esc_html__('URL is required', 'wpcopilot'), array('status' => 400));
        }

        require_once(ABSPATH . 'wp-admin/includes/file.php');
        require_once(ABSPATH . 'wp-admin/includes/media.php');
        require_once(ABSPATH . 'wp-admin/includes/image.php');

        // Download file to temp dir
        $temp_file = download_url($url);

        if (is_wp_error($temp_file)) {
            return new WP_Error('download_failed', $temp_file->get_error_message(), array('status' => 500));
        }

        // Array based on $_FILE as seen in PHP file uploads
        $file = array(
            'name'     => $filename ?: basename($url),
            'type'     => mime_content_type($temp_file),
            'tmp_name' => $temp_file,
            'error'    => 0,
            'size'     => filesize($temp_file),
        );

        $overrides = array(
            'test_form' => false,
            'test_size' => true,
        );

        // Move the temporary file into the uploads directory
        $results = wp_handle_sideload($file, $overrides);

        if (!empty($results['error'])) {
            return new WP_Error('upload_failed', $results['error'], array('status' => 500));
        }

        // Insert the attachment into the media library
        $attachment = array(
            'post_mime_type' => $results['type'],
            'post_title'     => preg_replace('/\.[^.]+$/', '', $results['file']),
            'post_content'   => '',
            'post_status'    => 'inherit'
        );

        $attach_id = wp_insert_attachment($attachment, $results['file']);

        // Generate attachment metadata
        $attach_data = wp_generate_attachment_metadata($attach_id, $results['file']);
        wp_update_attachment_metadata($attach_id, $attach_data);

        $response = array(
            'id'  => $attach_id,
            'url' => wp_get_attachment_url($attach_id),
        );

        return new WP_REST_Response($response, 200);
    }

    private function get_general_info() {
        return array(
            'site_title' => esc_html(get_bloginfo('name')),
            'tagline' => esc_html(get_bloginfo('description')),
            'wp_version' => esc_html(get_bloginfo('version')),
            'site_url' => esc_url(get_site_url()),
            'home_url' => esc_url(get_home_url()),
            'admin_email' => sanitize_email(get_option('admin_email')),
            'language' => esc_html(get_bloginfo('language')),
            'timezone' => esc_html(get_option('timezone_string')),
            'date_format' => esc_html(get_option('date_format')),
            'time_format' => esc_html(get_option('time_format')),
            'posts_per_page' => absint(get_option('posts_per_page')),
        );
    }

    private function get_theme_info() {
        $current_theme = wp_get_theme();
        return array(
            'name' => esc_html($current_theme->get('Name')),
            'version' => esc_html($current_theme->get('Version')),
            'author' => esc_html($current_theme->get('Author')),
            'author_uri' => esc_url($current_theme->get('AuthorURI')),
            'template' => esc_html($current_theme->get_template()),
            'stylesheet' => esc_html($current_theme->get_stylesheet()),
            'screenshot' => esc_url($current_theme->get_screenshot()),
            'description' => esc_html($current_theme->get('Description')),
            'tags' => array_map('esc_html', (array) $current_theme->get('Tags'))
        );
    }

    public function get_plugin_info() {
        if (!function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }
        $all_plugins = get_plugins();
        $active_plugins = get_option('active_plugins', array());
            
        $plugin_info = array();
        foreach ($all_plugins as $plugin_path => $plugin_data) {
            $plugin_info[] = array(
                'name' => esc_html($plugin_data['Name']),
                'version' => esc_html($plugin_data['Version']),
                'author' => esc_html($plugin_data['Author']),
                'description' => esc_html($plugin_data['Description']),
                'is_active' => in_array($plugin_path, $active_plugins, true)
            );
        }
        return new WP_REST_Response($plugin_info, 200);
    }

    private function get_wordpress_posts() {
        $args = array(
            'post_type' => 'post',
            'posts_per_page' => 10,
            'post_status' => 'publish'
        );
        $posts = get_posts($args);
        $post_data = array();
        foreach ($posts as $post) {
            $post_data[] = array(
                'ID' => absint($post->ID),
                'title' => esc_html($post->post_title),
                'date' => esc_html($post->post_date),
                'author' => esc_html(get_the_author_meta('display_name', $post->post_author)),
                'excerpt' => esc_html(get_the_excerpt($post))
            );
        }
        return $post_data;
    }

    private function get_menu_info() {
        $menus = wp_get_nav_menus();
        $menu_data = array();
        foreach ($menus as $menu) {
            $menu_data[] = array(
                'ID' => absint($menu->term_id),
                'name' => esc_html($menu->name),
                'slug' => esc_html($menu->slug),
                'locations' => array_map('esc_html', (array) get_nav_menu_locations())
            );
        }
        return $menu_data;
    }

    private function get_widget_info() {
        global $wp_registered_sidebars, $wp_registered_widgets;
        
        $widget_data = array();
        foreach ($wp_registered_sidebars as $sidebar) {
            $widgets = wp_get_sidebars_widgets();
            $sidebar_widgets = array();
            if (isset($widgets[$sidebar['id']])) {
                foreach ($widgets[$sidebar['id']] as $widget) {
                    if (isset($wp_registered_widgets[$widget])) {
                        $sidebar_widgets[] = esc_html($wp_registered_widgets[$widget]['name']);
                    }
                }
            }
            $widget_data[] = array(
                'name' => esc_html($sidebar['name']),
                'id' => esc_attr($sidebar['id']),
                'widgets' => $sidebar_widgets
            );
        }
        return $widget_data;
    }

    private function get_favicon() {
        $favicon_url = get_site_icon_url();
        return $favicon_url ? esc_url($favicon_url) : '';
    }

    private function get_site_logo() {
        $custom_logo_id = get_theme_mod('custom_logo');
        $logo_url = wp_get_attachment_image_url($custom_logo_id, 'full');
        return $logo_url ? esc_url($logo_url) : '';
    }

    public function add_admin_menu() {
        add_options_page(
            esc_html__('WPCopilot - wpc.dev API Settings', 'wpcopilot'),
            esc_html__('WPCopilot - wpc.dev API Key', 'wpcopilot'),
            'manage_options',
            'wpcopilot-api-settings',
            array($this, 'settings_page')
        );
    }

    public function register_settings() {
        register_setting('wpcopilot_api_settings', 'wpcopilot_api_key', 'sanitize_text_field');
    }

    public function settings_page() {
        ?>
        <div class="wrap">
            <h1><?php echo esc_html__('Wordpress Copilot API Settings', 'wpcopilot'); ?></h1>
            <form method="post" action="options.php">
                <?php
                    settings_fields('wpcopilot_api_settings');
                    do_settings_sections('wpcopilot_api_settings');
                ?>
                <table class="form-table">
                    <tr valign="top">
                        <th scope="row"><?php echo esc_html__('API Key', 'wpcopilot'); ?></th>
                        <td>
                            <input type="text" name="wpcopilot_api_key" value="<?php echo esc_attr($this->api_key); ?>" style="width: 100%; max-width: 400px;" />
                            <p class="description">
                                <?php echo esc_html__('API Key Status: ', 'wpcopilot'); ?>
                                <?php echo $this->api_key_status ? '<span style="color: green;">Valid</span>' : '<span style="color: red;">Invalid</span>'; ?>
                            </p>
                            <p class="description">
                                <?php echo esc_html__('Current API Key (for debug): ', 'wpcopilot'); ?>
                                <code><?php echo esc_html($this->api_key); ?></code>
                            </p>
                        </td>
                    </tr>
                </table>
                <?php submit_button(); ?>
            </form>
            <a href="<?php echo esc_url('https://wpc.dev/connect?wpurl=' . urlencode(get_site_url()) . '&api_key=' . urlencode(get_option('wpcopilot_api_key'))); ?>" class="button button-primary" target="_blank" rel="noopener noreferrer"><?php echo esc_html__('Connect to WPCopilot', 'wpcopilot'); ?></a>
        </div>
        <?php
    }

    public function add_settings_link($links) {
        $settings_link = '<a href="' . admin_url('options-general.php?page=wpcopilot-api-settings') . '">' . __('Settings', 'wpcopilot') . '</a>';
        array_unshift($links, $settings_link);
        return $links;
    }

    public function enqueue_admin_scripts() {
        wp_enqueue_style('wpcopilot-admin-style', plugins_url('css/admin-style.css', __FILE__));
        wp_enqueue_script('wpcopilot-admin-script', plugins_url('js/admin-script.js', __FILE__), array('jquery'), null, true);
    }

    public function add_chat_popup() {
        ?>
        <div id="wpcopilot-chat-popup" class="wpcopilot-chat-popup">
            <div class="chat-header">
                <h3><?php echo esc_html__('WordPress Copilot Chat', 'wpcopilot'); ?></h3>
                <button id="wpcopilot-minimize-chat" class="minimize-button">-</button>
            </div>
            <div class="chat-body">
                <iframe src="<?php echo esc_url('https://wpc.dev/chat'); ?>" frameborder="0"></iframe>
            </div>
        </div>
        <?php
    }

    public function install_plugin_file_endpoint($request) {
        $params = $request->get_json_params();
        $plugin_code = isset($params['plugin_code']) ? $params['plugin_code'] : '';
        $plugin_name = isset($params['plugin_name']) ? sanitize_file_name($params['plugin_name']) : '';
    
        if (empty($plugin_code) || empty($plugin_name)) {
            return new WP_Error('invalid_plugin_data', esc_html__('Plugin code and name are required.', 'wpcopilot'), array('status' => 400));
        }
    
        // Ensure the plugin name ends with .php
        if (!preg_match('/\.php$/', $plugin_name)) {
            $plugin_name .= '.php';
        }
    
        $plugin_dir = WP_PLUGIN_DIR . '/' . dirname($plugin_name);
        $plugin_file = $plugin_dir . '/' . basename($plugin_name);
    
        // Create plugin directory if it doesn't exist
        if (!file_exists($plugin_dir)) {
            wp_mkdir_p($plugin_dir);
        }
    
        // Write the plugin file
        $write_result = file_put_contents($plugin_file, $plugin_code);
    
        if ($write_result === false) {
            return new WP_Error('plugin_write_failed', esc_html__('Failed to write plugin file.', 'wpcopilot'), array('status' => 500));
        }
    
        // Activate the plugin
        $activate = activate_plugin($plugin_file);
    
        if (is_wp_error($activate)) {
            // If activation fails, delete the plugin file
            unlink($plugin_file);
            return new WP_Error('plugin_activation_failed', $activate->get_error_message(), array('status' => 500));
        }
    
        return new WP_REST_Response(array('message' => esc_html__('Plugin installed and activated successfully.', 'wpcopilot')), 200);
    }

    public function install_plugin_endpoint($request) {
        // if (!current_user_can('install_plugins')) {
        //     return new WP_Error('rest_forbidden', esc_html__('You do not have permission to install plugins.', 'wpcopilot'), array('status' => 403));
        // }

        $params = $request->get_json_params();
        $plugin_url = isset($params['plugin_url']) ? esc_url_raw($params['plugin_url']) : '';

        if (empty($plugin_url)) {
            return new WP_Error('invalid_plugin_url', esc_html__('Plugin URL is required.', 'wpcopilot'), array('status' => 400));
        }

        require_once ABSPATH . 'wp-admin/includes/file.php';
        require_once ABSPATH . 'wp-admin/includes/misc.php';
        require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
        require_once ABSPATH . 'wp-admin/includes/plugin-install.php';
        require_once ABSPATH . 'wp-admin/includes/plugin.php';

        // Download the plugin
        $download_link = $plugin_url;
        $upgrader = new Plugin_Upgrader(new WP_Ajax_Upgrader_Skin());
        $installed = $upgrader->install($download_link);

        if (is_wp_error($installed)) {
            return new WP_Error('plugin_install_failed', $installed->get_error_message(), array('status' => 500));
        }

        if (!$installed) {
            return new WP_Error('plugin_install_failed', esc_html__('Plugin installation failed for an unknown reason.', 'wpcopilot'), array('status' => 500));
        }

        // Activate the plugin
        $plugin_file = $upgrader->plugin_info();
        $activate = activate_plugin($plugin_file);

        if (is_wp_error($activate)) {
            return new WP_Error('plugin_activation_failed', $activate->get_error_message(), array('status' => 500));
        }

        return new WP_REST_Response(array('message' => esc_html__('Plugin installed and activated successfully.', 'wpcopilot')), 200);
    }
    public function remove_plugin_endpoint($request) {
        $params = $request->get_json_params();
        $plugin_slug = isset($params['plugin_slug']) ? sanitize_text_field($params['plugin_slug']) : '';

        if (empty($plugin_slug)) {
            return new WP_Error('invalid_plugin_slug', esc_html__('Plugin slug is required.', 'wpcopilot'), array('status' => 400));
        }

        if (!function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        $all_plugins = get_plugins();
        $plugin_file = '';

        foreach ($all_plugins as $file => $plugin) {
            if (strpos($file, $plugin_slug . '/') === 0 || $file === $plugin_slug . '.php') {
                $plugin_file = $file;
                break;
            }
        }

        if (empty($plugin_file)) {
            return new WP_Error('plugin_not_found', esc_html__('Plugin not found.', 'wpcopilot'), array('status' => 404));
        }

        // Deactivate the plugin if it's active
        if (is_plugin_active($plugin_file)) {
            deactivate_plugins($plugin_file);
        }

        // Delete the plugin
        $deleted = delete_plugins(array($plugin_file));

        if (is_wp_error($deleted)) {
            return new WP_Error('plugin_deletion_failed', $deleted->get_error_message(), array('status' => 500));
        }

        if (!$deleted) {
            return new WP_Error('plugin_deletion_failed', esc_html__('Plugin removal failed for an unknown reason.', 'wpcopilot'), array('status' => 500));
        }

        return new WP_REST_Response(array('message' => esc_html__('Plugin removed successfully.', 'wpcopilot')), 200);
    }
    public function get_admin_login_link($request) {
        if (!function_exists('wp_create_nonce')) {
            require_once(ABSPATH . 'wp-includes/pluggable.php');
        }

        // Get the first admin user
        $admin_users = get_users(array('role' => 'administrator', 'number' => 1));
        if (empty($admin_users)) {
            return new WP_Error('no_admin', esc_html__('No administrator account found.', 'wpcopilot'), array('status' => 400));
        }

        $admin_user = $admin_users[0];

        $nonce = wp_create_nonce('auto-login-nonce');
        $auto_login_url = add_query_arg(array(
            'action' => 'auto_login',
            'user_id' => $admin_user->ID,
            'nonce' => $nonce
        ), admin_url('admin-ajax.php'));

        return new WP_REST_Response(array('auto_login_url' => $auto_login_url), 200);
    }

    public function handle_auto_login() {
        if (isset($_GET['action']) && $_GET['action'] === 'auto_login') {
            $this->auto_login();
        }
    }

    public function auto_login() {
        error_log('auto_login function called');

        $user_id = isset($_GET['user_id']) ? intval($_GET['user_id']) : 0;
        $nonce = isset($_GET['nonce']) ? sanitize_text_field($_GET['nonce']) : '';

        // Log the received parameters
        error_log('Received user_id: ' . $user_id);
        error_log('Received nonce: ' . $nonce);

        $nonce_verification = wp_verify_nonce($nonce, 'auto-login-nonce');
        
        // Log the nonce verification result
        error_log('Nonce verification result: ' . ($nonce_verification ? 'true' : 'false'));

        
        // Return user_id and nonce for debugging
        // wp_send_json(array(
        //     'user_id' => $user_id,
        //     'nonce' => $nonce,
        //     'wp_verify_nonce' => wp_verify_nonce($nonce, 'auto-login-nonce')
        // ));
        // return;
        if (!wp_verify_nonce($nonce, 'auto-login-nonce')) {
            wp_die(esc_html__('Security check failed.', 'wpcopilot'));
        }

        $user = get_user_by('id', $user_id);
        if ($user && user_can($user, 'administrator')) {
            wp_clear_auth_cookie();
            wp_set_current_user($user_id, $user->user_login);
            wp_set_auth_cookie($user_id);
            do_action('wp_login', $user->user_login, $user);
            error_log('User logged in successfully: ' . $user->user_login);
            wp_redirect(admin_url());
            exit;
        }
        error_log('Auto-login failed');

        wp_die(esc_html__('Auto-login failed.', 'wpcopilot'));
    }
}

new WPCopilot_Options_Access();