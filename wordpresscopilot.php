<?php
/**
 * Plugin Name: Wordpress Copilot  
 * Description: AI-Powered Wordpress Development
 * Version: 0.0.6
 * Author: Wordpress Copliot
 * Author URI: https://wordpresscopilot.com
 * License URI: http://www.gnu.org/licenses/gpl-2.0.txt
 * Text Domain: wordpresscopilot
 * Domain Path: /languages
 */

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

class WordpressCopilot_Options_Access {
    private $api_key;
    private $api_key_status;

    public function __construct() {
        $this->api_key = get_option('wordpresscopilot_api_key', $this->generate_default_api_key());
        $this->api_key_status = $this->check_api_key_status();
        add_action('rest_api_init', array($this, 'register_api_endpoints'));
        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_action('admin_init', array($this, 'register_settings'));
        add_filter('plugin_action_links_' . plugin_basename(__FILE__), array($this, 'add_settings_link'));
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
        register_rest_route('wordpresscopilot/v1', '/site-info', array(
            'methods' => 'GET',
            'callback' => array($this, 'get_site_info'),
            'permission_callback' => array($this, 'check_permission')
        ));

        register_rest_route('wordpresscopilot/v1', '/health', array(
            'methods' => 'GET',
            'callback' => array($this, 'get_health_check'),
            'permission_callback' => '__return_true'
        ));

        register_rest_route('wordpresscopilot/v1', '/run-sql', array(
            'methods' => 'POST',
            'callback' => array($this, 'run_sql_query'),
            'permission_callback' => array($this, 'check_permission')
        ));

        register_rest_route('wordpresscopilot/v1', '/run-php', array(
            'methods' => 'POST',
            'callback' => array($this, 'run_php_code'),
            'permission_callback' => array($this, 'check_permission')
        ));
    }

    public function check_permission() {
        $provided_key = isset($_GET['api_key']) ? sanitize_text_field($_GET['api_key']) : '';
        if (!wp_check_invalid_utf8($provided_key) && $provided_key === $this->api_key) {
            return true;
        }
        return new WP_Error('rest_forbidden', esc_html__('Invalid API Key', 'wordpresscopilot'), array('status' => 403));
    }

    public function get_site_info() {
        $response = array(
            'agent_name' => 'WordpressCopilot',
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
            'message' => esc_html__('WordpressCopilot API is functioning correctly', 'wordpresscopilot'),
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
            return new WP_Error('invalid_query', esc_html__('SQL query is required', 'wordpresscopilot'), array('status' => 400));
        }

        $allowed_operations = array('SELECT', 'SHOW', 'DESCRIBE', 'DESC');
        $operation = strtoupper(substr(trim($query), 0, 6));
        
        if (!in_array($operation, $allowed_operations, true)) {
            return new WP_Error('forbidden_operation', esc_html__('Only SELECT, SHOW, DESCRIBE, and DESC operations are allowed', 'wordpresscopilot'), array('status' => 403));
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
            return new WP_Error('invalid_code', esc_html__('PHP code is required', 'wordpresscopilot'), array('status' => 400));
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
            esc_html__('Wordpresss Copilot API Settings', 'wordpresscopilot'),
            esc_html__('Wordpresss Copilot API', 'wordpresscopilot'),
            'manage_options',
            'wordpresscopilot-api-settings',
            array($this, 'settings_page')
        );
    }

    public function register_settings() {
        register_setting('wordpresscopilot_api_settings', 'wordpresscopilot_api_key', 'sanitize_text_field');
    }

    public function settings_page() {
        ?>
        <div class="wrap">
            <h1><?php echo esc_html__('Wordpress Copilot API Settings', 'wordpresscopilot'); ?></h1>
            <form method="post" action="options.php">
                <?php
                    settings_fields('wordpresscopilot_api_settings');
                    do_settings_sections('wordpresscopilot_api_settings');
                ?>
                <table class="form-table">
                    <tr valign="top">
                        <th scope="row"><?php echo esc_html__('API Key', 'wordpresscopilot'); ?></th>
                        <td>
                            <input type="text" name="wordpresscopilot_api_key" value="<?php echo esc_attr(get_option('wordpresscopilot_api_key')); ?>" />
                            <p class="description">
                                <?php echo esc_html__('API Key Status: ', 'wordpresscopilot'); ?>
                                <?php echo $this->api_key_status ? '<span style="color: green;">Valid</span>' : '<span style="color: red;">Invalid</span>'; ?>
                            </p>
                            <p class="description">
                                <?php echo esc_html__('Current API Key (for debug): ', 'wordpresscopilot'); ?>
                                <code><?php echo esc_html($this->api_key); ?></code>
                            </p>
                        </td>
                    </tr>
                </table>
                <?php submit_button(); ?>
            </form>
            <a href="<?php echo esc_url('https://wordpresscopilot.com/connect?wpurl=' . urlencode(get_site_url()) . '&api_key=' . urlencode(get_option('wordpresscopilot_api_key'))); ?>" class="button button-primary" target="_blank" rel="noopener noreferrer"><?php echo esc_html__('Connect to Wordpress Copilot', 'wordpresscopilot'); ?></a>
        </div>
        <?php
    }

    public function add_settings_link($links) {
        $settings_link = '<a href="' . admin_url('options-general.php?page=wordpresscopilot-api-settings') . '">' . __('Settings', 'wordpresscopilot') . '</a>';
        array_unshift($links, $settings_link);
        return $links;
    }
}

new WordpressCopilot_Options_Access();