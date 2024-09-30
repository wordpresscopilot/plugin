<?php
/**
 * Plugin Name: WPCopilot  
 * Description: AI-Powered Wordpress Development
 * Version: 0.0.8
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
        $this->plugin_version = '0.0.8';
        add_action('rest_api_init', array($this, 'register_api_endpoints'));
        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_action('admin_init', array($this, 'register_settings'));
        add_filter('plugin_action_links_' . plugin_basename(__FILE__), array($this, 'add_settings_link'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_scripts'));
        add_action('admin_footer', array($this, 'add_chat_popup'));
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

    public function get_site_info() {
        $response = array(
            'agent_name' => 'WPCopilot',
            'plugin_version' => $this->plugin_version,
            'general_info' => $this->get_general_info(),
            'theme_info' => $this->get_theme_info(),
            'plugin_info' => $this->get_plugin_info(),
            'posts' => $this->get_wordpress_posts(),
            'menus' => $this->get_menu_info(),
            'widgets' => $this->get_widget_info(),
            'favicon' => $this->get_favicon(),
            'site_logo' => $this->get_site_logo(),
        );
        return new WP_REST_Response($response, 200);
    }

    public function get_health_check($request) {
        $response = array(
            'status' => 'ok',
            'message' => esc_html__('WPCopilot API is functioning correctly', 'wpcopilot'),
            'timestamp' => current_time('mysql')
        );

        $provided_key = isset($_GET['api_key']) ? sanitize_text_field($_GET['api_key']) : '';
        if (!empty($provided_key)) {
            $response['api_key_valid'] = (!wp_check_invalid_utf8($provided_key) && $provided_key === $this->api_key);
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

        $allowed_operations = array('SELECT', 'SHOW', 'DESCRIBE', 'DESC');
        $operation = strtoupper(substr(trim($query), 0, 6));
        
        if (!in_array($operation, $allowed_operations, true)) {
            return new WP_Error('forbidden_operation', esc_html__('Only SELECT, SHOW, DESCRIBE, and DESC operations are allowed', 'wpcopilot'), array('status' => 403));
        }

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

    private function get_plugin_info() {
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
        return $plugin_info;
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
            <a href="<?php echo esc_url('https://wpc.dev/connect?wpurl=' . urlencode(get_site_url()) . '&api_key=' . urlencode(get_option('wpcopilot_api_key'))); ?>" class="button button-primary" target="_blank" rel="noopener noreferrer"><?php echo esc_html__('Connect to Wordpress Copilot', 'wpcopilot'); ?></a>
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
}

new WPCopilot_Options_Access();