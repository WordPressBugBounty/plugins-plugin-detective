<?php
// use when needed to compare wp version for compatibility
global $global_wp_version;

function pd_maybe_require( $path ) {
	if ( file_exists( $path ) ) {
		require_once $path;
	}
	
	if( !empty( $wp_version ) ){
		global $global_wp_version;
		$global_wp_version = $wp_version;
	}
}
/**
 * Troubleshoot Settings.
 *
 * @since   0.0.0
 * @package Troubleshoot
 */

/**
 * Troubleshoot Settings.
 *
 * @since 0.0.0
 */
class PDT_Settings {
	/**
	 * Parent plugin class.
	 *
	 * @since 0.0.0
	 *
	 * @var   Troubleshoot
	 */
	protected $plugin = null;

	/**
	 * Constructor.
	 *
	 * @since  0.0.0
	 *
	 * @param  Troubleshoot $plugin Main plugin object.
	 */
	public function __construct( $plugin ) {
		$this->plugin = $plugin;
		$this->hooks();
	}

	/**
	 * Initiate our hooks.
	 *
	 * @since  0.0.0
	 */
	public function hooks() {

	}
}

/**
 * Used to set up and fix common variables and include
 * the WordPress procedural and class library.
 *
 * Allows for some configuration in wp-config.php (see default-constants.php)
 *
 * @package WordPress
 */

/**
 * Stores the location of the WordPress directory of functions, classes, and core content.
 *
 * @since 1.0.0
 */
define( 'WPINC', 'wp-includes' );

/*
 * These can't be directly globalized in version.php. When updating,
 * we're including version.php from another installation and don't want
 * these values to be overridden if already set.
 */
global $wp_version, $wp_db_version, $tinymce_version, $required_php_version, $required_mysql_version, $wp_local_package;
pd_maybe_require( ABSPATH . WPINC . '/version.php' );
pd_maybe_require( ABSPATH . WPINC . '/compat.php' );
pd_maybe_require( ABSPATH . WPINC . '/load.php' );

// Include files required for initialization.
@include( ABSPATH . WPINC . '/class-wp-paused-extensions-storage.php' );
@include( ABSPATH . WPINC . '/class-wp-exception.php' );
@include( ABSPATH . WPINC . '/class-wp-fatal-error-handler.php' );
@include( ABSPATH . WPINC . '/class-wp-recovery-mode-cookie-service.php' );
@include( ABSPATH . WPINC . '/class-wp-recovery-mode-key-service.php' );
@include( ABSPATH . WPINC . '/class-wp-recovery-mode-link-service.php' );
@include( ABSPATH . WPINC . '/class-wp-recovery-mode-email-service.php' );
@include( ABSPATH . WPINC . '/class-wp-recovery-mode.php' );
@include( ABSPATH . WPINC . '/error-protection.php' );
@include( ABSPATH . WPINC . '/default-constants.php' );
require_once( ABSPATH . WPINC . '/plugin.php' );

/**
 * If not already configured, `$blog_id` will default to 1 in a single site
 * configuration. In multisite, it will be overridden by default in ms-settings.php.
 *
 * @global int $blog_id
 * @since 2.0.0
 */
global $blog_id;
global $table_prefix;

// Set initial default constants including WP_MEMORY_LIMIT, WP_MAX_MEMORY_LIMIT, WP_DEBUG, SCRIPT_DEBUG, WP_CONTENT_DIR and WP_CACHE.
wp_initial_constants();

if ( function_exists( 'wp_register_fatal_error_handler' ) ) {
	// Make sure we register the shutdown handler for fatal errors as soon as possible.
	wp_register_fatal_error_handler();
}

// Check for the required PHP version and for the MySQL extension or a database drop-in.
wp_check_php_mysql_versions();

// Disable magic quotes at runtime. Magic quotes are added using wpdb later in wp-settings.php.
@ini_set( 'magic_quotes_runtime', 0 );
@ini_set( 'magic_quotes_sybase',  0 );

// WordPress calculates offsets from UTC.
date_default_timezone_set( 'UTC' );

// Standardize $_SERVER variables across setups.
wp_fix_server_vars();

// Check if we have received a request due to missing favicon.ico
wp_favicon_request();

// Check if we're in maintenance mode.
// wp_maintenance();

// Start loading timer.
timer_start();

// Check if we're in WP_DEBUG mode.
wp_debug_mode();

/**
 * Filters whether to enable loading of the advanced-cache.php drop-in.
 *
 * This filter runs before it can be used by plugins. It is designed for non-web
 * run-times. If false is returned, advanced-cache.php will never be loaded.
 *
 * @since 4.6.0
 *
 * @param bool $enable_advanced_cache Whether to enable loading advanced-cache.php (if present).
 *                                    Default true.
 */

/* PD: Start cache disable */
// if ( WP_CACHE && apply_filters( 'enable_loading_advanced_cache_dropin', true ) ) {
	// For an advanced caching plugin to use. Uses a static drop-in because you would only want one.
	// WP_DEBUG ? include( WP_CONTENT_DIR . '/advanced-cache.php' ) : @include( WP_CONTENT_DIR . '/advanced-cache.php' );
// Re-initialize any hooks added manually by advanced-cache.php
	// if ( $wp_filter ) {
	// 	$wp_filter = WP_Hook::build_preinitialized_hooks( $wp_filter );
	// }
/* PD: End cache disable */



// Define WP_LANG_DIR if not set.
wp_set_lang_dir();

// Load early WordPress files.
pd_maybe_require( ABSPATH . WPINC . '/class-wp-list-util.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-token-map.php' );
pd_maybe_require( ABSPATH . WPINC . '/formatting.php' );
pd_maybe_require( ABSPATH . WPINC . '/functions.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-matchesmapregex.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-error.php' );
pd_maybe_require( ABSPATH . WPINC . '/pomo/mo.php' );
pd_maybe_require( ABSPATH . WPINC . '/l10n/class-wp-translation-controller.php' );
pd_maybe_require( ABSPATH . WPINC . '/l10n/class-wp-translations.php' );
pd_maybe_require( ABSPATH . WPINC . '/l10n/class-wp-translation-file.php' );
pd_maybe_require( ABSPATH . WPINC . '/l10n/class-wp-translation-file-mo.php' );
pd_maybe_require( ABSPATH . WPINC . '/l10n/class-wp-translation-file-php.php' );

// Include the wpdb class and, if present, a db.php database drop-in.
global $wpdb;
require_wp_db();
// Set the database table prefix and the format specifiers for database table columns.
$GLOBALS['table_prefix'] = $table_prefix;
wp_set_wpdb_vars();

// Start the WordPress object cache, or an external object cache if the drop-in is present.
wp_start_object_cache();

// Attach the default filters.
pd_maybe_require( ABSPATH . WPINC . '/default-filters.php' );

// Initialize multisite if enabled.
if ( is_multisite() ) {
	pd_maybe_require( ABSPATH . WPINC . '/class-wp-site-query.php' );
	pd_maybe_require( ABSPATH . WPINC . '/class-wp-network-query.php' );
	pd_maybe_require( ABSPATH . WPINC . '/ms-blogs.php' );
	pd_maybe_require( ABSPATH . WPINC . '/ms-settings.php' );
} elseif ( ! defined( 'MULTISITE' ) ) {
	define( 'MULTISITE', false );
}

register_shutdown_function( 'shutdown_action_hook' );

// Stop most of WordPress from being loaded if we just want the basics.
if ( SHORTINIT )
	return false;

// Load the L10n library.
pd_maybe_require( ABSPATH . WPINC . '/l10n.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-textdomain-registry.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-locale.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-locale-switcher.php' );

// Run the installer if WordPress is not installed.
/* PD: Start wp_not_installed() disable */

// wp_not_installed();

/* PD: End wp_not_installed() disable */


// Load most of WordPress.
pd_maybe_require( ABSPATH . WPINC . '/class-wp-walker.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-ajax-response.php' );
pd_maybe_require( ABSPATH . WPINC . '/capabilities.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-roles.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-role.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-user.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-query.php' );
pd_maybe_require( ABSPATH . WPINC . '/query.php' );
pd_maybe_require( ABSPATH . WPINC . '/date.php' );
pd_maybe_require( ABSPATH . WPINC . '/theme.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-theme.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-theme-json-schema.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-theme-json-data.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-theme-json.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-theme-json-resolver.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-duotone.php' );
pd_maybe_require( ABSPATH . WPINC . '/global-styles-and-settings.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-block-template.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-block-templates-registry.php' );
pd_maybe_require( ABSPATH . WPINC . '/block-template-utils.php' );
pd_maybe_require( ABSPATH . WPINC . '/block-template.php' );
pd_maybe_require( ABSPATH . WPINC . '/theme-templates.php' );
pd_maybe_require( ABSPATH . WPINC . '/theme-previews.php' );
pd_maybe_require( ABSPATH . WPINC . '/template.php' );
pd_maybe_require( ABSPATH . WPINC . '/https-detection.php' );
pd_maybe_require( ABSPATH . WPINC . '/https-migration.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-user-request.php' );
pd_maybe_require( ABSPATH . WPINC . '/user.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-user-query.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-session-tokens.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-user-meta-session-tokens.php' );
pd_maybe_require( ABSPATH . WPINC . '/meta.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-meta-query.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-metadata-lazyloader.php' );
pd_maybe_require( ABSPATH . WPINC . '/general-template.php' );
pd_maybe_require( ABSPATH . WPINC . '/link-template.php' );


pd_maybe_require( ABSPATH . WPINC . '/author-template.php' );
pd_maybe_require( ABSPATH . WPINC . '/robots-template.php' );
pd_maybe_require( ABSPATH . WPINC . '/post.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-walker-page.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-walker-page-dropdown.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-post-type.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-post.php' );
pd_maybe_require( ABSPATH . WPINC . '/post-template.php' );
pd_maybe_require( ABSPATH . WPINC . '/revision.php' );
pd_maybe_require( ABSPATH . WPINC . '/post-formats.php' );
pd_maybe_require( ABSPATH . WPINC . '/post-thumbnail-template.php' );
pd_maybe_require( ABSPATH . WPINC . '/category.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-walker-category.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-walker-category-dropdown.php' );
pd_maybe_require( ABSPATH . WPINC . '/category-template.php' );
pd_maybe_require( ABSPATH . WPINC . '/comment.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-comment.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-comment-query.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-walker-comment.php' );
pd_maybe_require( ABSPATH . WPINC . '/comment-template.php' );
pd_maybe_require( ABSPATH . WPINC . '/rewrite.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-rewrite.php' );
pd_maybe_require( ABSPATH . WPINC . '/feed.php' );
pd_maybe_require( ABSPATH . WPINC . '/bookmark.php' );
pd_maybe_require( ABSPATH . WPINC . '/bookmark-template.php' );
pd_maybe_require( ABSPATH . WPINC . '/kses.php' );
pd_maybe_require( ABSPATH . WPINC . '/cron.php' );
pd_maybe_require( ABSPATH . WPINC . '/deprecated.php' );
pd_maybe_require( ABSPATH . WPINC . '/script-loader.php' );
pd_maybe_require( ABSPATH . WPINC . '/taxonomy.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-taxonomy.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-term.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-term-query.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-tax-query.php' );
pd_maybe_require( ABSPATH . WPINC . '/update.php' );
pd_maybe_require( ABSPATH . WPINC . '/canonical.php' );
pd_maybe_require( ABSPATH . WPINC . '/shortcodes.php' );
pd_maybe_require( ABSPATH . WPINC . '/embed.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-embed.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-oembed.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-oembed-controller.php' );
pd_maybe_require( ABSPATH . WPINC . '/media.php' );
pd_maybe_require( ABSPATH . WPINC . '/http.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-http.php' );
pd_maybe_require( ABSPATH . WPINC . '/html-api/html5-named-character-references.php' );
pd_maybe_require( ABSPATH . WPINC . '/html-api/class-wp-html-attribute-token.php' );
pd_maybe_require( ABSPATH . WPINC . '/html-api/class-wp-html-span.php' );
pd_maybe_require( ABSPATH . WPINC . '/html-api/class-wp-html-doctype-info.php' );
pd_maybe_require( ABSPATH . WPINC . '/html-api/class-wp-html-text-replacement.php' );
pd_maybe_require( ABSPATH . WPINC . '/html-api/class-wp-html-decoder.php' );
pd_maybe_require( ABSPATH . WPINC . '/html-api/class-wp-html-tag-processor.php' );
pd_maybe_require( ABSPATH . WPINC . '/html-api/class-wp-html-unsupported-exception.php' );
pd_maybe_require( ABSPATH . WPINC . '/html-api/class-wp-html-active-formatting-elements.php' );
pd_maybe_require( ABSPATH . WPINC . '/html-api/class-wp-html-open-elements.php' );
pd_maybe_require( ABSPATH . WPINC . '/html-api/class-wp-html-token.php' );
pd_maybe_require( ABSPATH . WPINC . '/html-api/class-wp-html-stack-event.php' );
pd_maybe_require( ABSPATH . WPINC . '/html-api/class-wp-html-processor-state.php' );
pd_maybe_require( ABSPATH . WPINC . '/html-api/class-wp-html-processor.php' );
// pd_maybe_require( ABSPATH . WPINC . '/class-wp-http.php' ); // fatal error if both are here. class-http is better for backcompat. class-wp-http was introduced in 5.9
pd_maybe_require( ABSPATH . WPINC . '/class-wp-http-streams.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-http-curl.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-http-proxy.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-http-cookie.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-http-encoding.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-http-response.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-http-requests-response.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-http-requests-hooks.php' );
pd_maybe_require( ABSPATH . WPINC . '/widgets.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-widget.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-widget-factory.php' );
pd_maybe_require( ABSPATH . WPINC . '/nav-menu-template.php' );
pd_maybe_require( ABSPATH . WPINC . '/nav-menu.php' );
pd_maybe_require( ABSPATH . WPINC . '/admin-bar.php' );
pd_maybe_require( ABSPATH . WPINC . '/rest-api.php' );
pd_maybe_require( ABSPATH . WPINC . '/rest-api/class-wp-rest-server.php' );
pd_maybe_require( ABSPATH . WPINC . '/rest-api/class-wp-rest-response.php' );
pd_maybe_require( ABSPATH . WPINC . '/rest-api/class-wp-rest-request.php' );
pd_maybe_require( ABSPATH . WPINC . '/rest-api/endpoints/class-wp-rest-controller.php' );
pd_maybe_require( ABSPATH . WPINC . '/rest-api/endpoints/class-wp-rest-posts-controller.php' );
pd_maybe_require( ABSPATH . WPINC . '/rest-api/endpoints/class-wp-rest-attachments-controller.php' );
pd_maybe_require( ABSPATH . WPINC . '/rest-api/endpoints/class-wp-rest-global-styles-controller.php' );
pd_maybe_require( ABSPATH . WPINC . '/rest-api/endpoints/class-wp-rest-post-types-controller.php' );
pd_maybe_require( ABSPATH . WPINC . '/rest-api/endpoints/class-wp-rest-post-statuses-controller.php' );
pd_maybe_require( ABSPATH . WPINC . '/rest-api/endpoints/class-wp-rest-revisions-controller.php' );
pd_maybe_require( ABSPATH . WPINC . '/rest-api/endpoints/class-wp-rest-global-styles-revisions-controller.php' );
pd_maybe_require( ABSPATH . WPINC . '/rest-api/endpoints/class-wp-rest-autosaves-controller.php' );
pd_maybe_require( ABSPATH . WPINC . '/rest-api/endpoints/class-wp-rest-taxonomies-controller.php' );
pd_maybe_require( ABSPATH . WPINC . '/rest-api/endpoints/class-wp-rest-terms-controller.php' );
pd_maybe_require( ABSPATH . WPINC . '/rest-api/endpoints/class-wp-rest-menu-items-controller.php' );
pd_maybe_require( ABSPATH . WPINC . '/rest-api/endpoints/class-wp-rest-menus-controller.php' );
pd_maybe_require( ABSPATH . WPINC . '/rest-api/endpoints/class-wp-rest-menu-locations-controller.php' );
pd_maybe_require( ABSPATH . WPINC . '/rest-api/endpoints/class-wp-rest-users-controller.php' );
pd_maybe_require( ABSPATH . WPINC . '/rest-api/endpoints/class-wp-rest-comments-controller.php' );
pd_maybe_require( ABSPATH . WPINC . '/rest-api/endpoints/class-wp-rest-search-controller.php' );
pd_maybe_require( ABSPATH . WPINC . '/rest-api/endpoints/class-wp-rest-blocks-controller.php' );
pd_maybe_require( ABSPATH . WPINC . '/rest-api/endpoints/class-wp-rest-block-types-controller.php' );
pd_maybe_require( ABSPATH . WPINC . '/rest-api/endpoints/class-wp-rest-block-renderer-controller.php' );
pd_maybe_require( ABSPATH . WPINC . '/rest-api/endpoints/class-wp-rest-settings-controller.php' );
pd_maybe_require( ABSPATH . WPINC . '/rest-api/endpoints/class-wp-rest-themes-controller.php' );
pd_maybe_require( ABSPATH . WPINC . '/rest-api/endpoints/class-wp-rest-plugins-controller.php' );
pd_maybe_require( ABSPATH . WPINC . '/rest-api/endpoints/class-wp-rest-block-directory-controller.php' );
pd_maybe_require( ABSPATH . WPINC . '/rest-api/endpoints/class-wp-rest-edit-site-export-controller.php' );
pd_maybe_require( ABSPATH . WPINC . '/rest-api/endpoints/class-wp-rest-pattern-directory-controller.php' );
pd_maybe_require( ABSPATH . WPINC . '/rest-api/endpoints/class-wp-rest-application-passwords-controller.php' );
pd_maybe_require( ABSPATH . WPINC . '/rest-api/endpoints/class-wp-rest-site-health-controller.php' );
pd_maybe_require( ABSPATH . WPINC . '/rest-api/endpoints/class-wp-rest-sidebars-controller.php' );
pd_maybe_require( ABSPATH . WPINC . '/rest-api/endpoints/class-wp-rest-widget-types-controller.php' );
pd_maybe_require( ABSPATH . WPINC . '/rest-api/endpoints/class-wp-rest-widgets-controller.php' );
pd_maybe_require( ABSPATH . WPINC . '/rest-api/endpoints/class-wp-rest-templates-controller.php' );
pd_maybe_require( ABSPATH . WPINC . '/rest-api/endpoints/class-wp-rest-url-details-controller.php' );
pd_maybe_require( ABSPATH . WPINC . '/rest-api/endpoints/class-wp-rest-navigation-fallback-controller.php' );
pd_maybe_require( ABSPATH . WPINC . '/rest-api/endpoints/class-wp-rest-font-families-controller.php' );
pd_maybe_require( ABSPATH . WPINC . '/rest-api/endpoints/class-wp-rest-font-faces-controller.php' );
pd_maybe_require( ABSPATH . WPINC . '/rest-api/endpoints/class-wp-rest-font-collections-controller.php' );
pd_maybe_require( ABSPATH . WPINC . '/rest-api/fields/class-wp-rest-meta-fields.php' );
pd_maybe_require( ABSPATH . WPINC . '/rest-api/fields/class-wp-rest-comment-meta-fields.php' );
pd_maybe_require( ABSPATH . WPINC . '/rest-api/fields/class-wp-rest-post-meta-fields.php' );
pd_maybe_require( ABSPATH . WPINC . '/rest-api/fields/class-wp-rest-term-meta-fields.php' );
pd_maybe_require( ABSPATH . WPINC . '/rest-api/fields/class-wp-rest-user-meta-fields.php' );
pd_maybe_require( ABSPATH . WPINC . '/rest-api/search/class-wp-rest-search-handler.php' );
pd_maybe_require( ABSPATH . WPINC . '/rest-api/search/class-wp-rest-post-search-handler.php' );

pd_maybe_require( ABSPATH . WPINC . '/sitemaps.php' );
pd_maybe_require( ABSPATH . WPINC . '/sitemaps/class-wp-sitemaps.php' );
pd_maybe_require( ABSPATH . WPINC . '/sitemaps/class-wp-sitemaps-index.php' );
pd_maybe_require( ABSPATH . WPINC . '/sitemaps/class-wp-sitemaps-provider.php' );
pd_maybe_require( ABSPATH . WPINC . '/sitemaps/class-wp-sitemaps-registry.php' );
pd_maybe_require( ABSPATH . WPINC . '/sitemaps/class-wp-sitemaps-renderer.php' );
pd_maybe_require( ABSPATH . WPINC . '/sitemaps/class-wp-sitemaps-stylesheet.php' );
pd_maybe_require( ABSPATH . WPINC . '/sitemaps/providers/class-wp-sitemaps-posts.php' );
pd_maybe_require( ABSPATH . WPINC . '/sitemaps/providers/class-wp-sitemaps-taxonomies.php' );
pd_maybe_require( ABSPATH . WPINC . '/sitemaps/providers/class-wp-sitemaps-users.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-block-bindings-source.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-block-bindings-registry.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-block-editor-context.php' );


pd_maybe_require( ABSPATH . WPINC . '/class-wp-block-type.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-block-pattern-categories-registry.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-block-patterns-registry.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-block-styles-registry.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-block-type-registry.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-block.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-block-list.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-block-metadata-registry.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-block-parser.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-classic-to-block-menu-converter.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-navigation-fallback.php' );
pd_maybe_require( ABSPATH . WPINC . '/block-bindings.php' );
pd_maybe_require( ABSPATH . WPINC . '/block-bindings/pattern-overrides.php' );
pd_maybe_require( ABSPATH . WPINC . '/block-bindings/post-meta.php' );
pd_maybe_require( ABSPATH . WPINC . '/blocks.php' );
pd_maybe_require( ABSPATH . WPINC . '/blocks/index.php' );
pd_maybe_require( ABSPATH . WPINC . '/block-editor.php' );
pd_maybe_require( ABSPATH . WPINC . '/block-patterns.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-block-supports.php' );
pd_maybe_require( ABSPATH . WPINC . '/block-supports/utils.php' );
pd_maybe_require( ABSPATH . WPINC . '/block-supports/align.php' );
pd_maybe_require( ABSPATH . WPINC . '/block-supports/custom-classname.php' );
pd_maybe_require( ABSPATH . WPINC . '/block-supports/generated-classname.php' );
pd_maybe_require( ABSPATH . WPINC . '/block-supports/settings.php' );
pd_maybe_require( ABSPATH . WPINC . '/block-supports/elements.php' );
pd_maybe_require( ABSPATH . WPINC . '/block-supports/colors.php' );
pd_maybe_require( ABSPATH . WPINC . '/block-supports/typography.php' );
pd_maybe_require( ABSPATH . WPINC . '/block-supports/border.php' );
pd_maybe_require( ABSPATH . WPINC . '/block-supports/layout.php' );
pd_maybe_require( ABSPATH . WPINC . '/block-supports/position.php' );
pd_maybe_require( ABSPATH . WPINC . '/block-supports/spacing.php' );
pd_maybe_require( ABSPATH . WPINC . '/block-supports/dimensions.php' );
pd_maybe_require( ABSPATH . WPINC . '/block-supports/duotone.php' );
pd_maybe_require( ABSPATH . WPINC . '/block-supports/shadow.php' );
pd_maybe_require( ABSPATH . WPINC . '/block-supports/background.php' );
pd_maybe_require( ABSPATH . WPINC . '/block-supports/block-style-variations.php' );

pd_maybe_require( ABSPATH . WPINC . '/navigation-fallback.php' );
pd_maybe_require( ABSPATH . WPINC . '/style-engine.php' );
pd_maybe_require( ABSPATH . WPINC . '/style-engine/class-wp-style-engine.php' );
pd_maybe_require( ABSPATH . WPINC . '/style-engine/class-wp-style-engine-css-declarations.php' );
pd_maybe_require( ABSPATH . WPINC . '/style-engine/class-wp-style-engine-css-rule.php' );
pd_maybe_require( ABSPATH . WPINC . '/style-engine/class-wp-style-engine-css-rules-store.php' );
pd_maybe_require( ABSPATH . WPINC . '/style-engine/class-wp-style-engine-processor.php' );
pd_maybe_require( ABSPATH . WPINC . '/fonts/class-wp-font-face-resolver.php' );
pd_maybe_require( ABSPATH . WPINC . '/fonts/class-wp-font-collection.php' );
pd_maybe_require( ABSPATH . WPINC . '/fonts/class-wp-font-face.php' );
pd_maybe_require( ABSPATH . WPINC . '/fonts/class-wp-font-library.php' );
pd_maybe_require( ABSPATH . WPINC . '/fonts/class-wp-font-utils.php' );
pd_maybe_require( ABSPATH . WPINC . '/fonts.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-script-modules.php' );
pd_maybe_require( ABSPATH . WPINC . '/script-modules.php' );
pd_maybe_require( ABSPATH . WPINC . '/interactivity-api/class-wp-interactivity-api.php' );
pd_maybe_require( ABSPATH . WPINC . '/interactivity-api/class-wp-interactivity-api-directives-processor.php' );
pd_maybe_require( ABSPATH . WPINC . '/interactivity-api/interactivity-api.php' );
pd_maybe_require( ABSPATH . WPINC . '/class-wp-plugin-dependencies.php' );

if ( function_exists( 'wp_script_modules' ) ) {
	add_action( 'after_setup_theme', array( wp_script_modules(), 'add_hooks' ) );
}
if ( function_exists( 'wp_interactivity' ) ) {
	add_action( 'after_setup_theme', array( wp_interactivity(), 'add_hooks' ) );
}

/* PD: Start bail out early */
// return;
/* PD: End bail out early */
$GLOBALS['wp_embed'] = new WP_Embed();

/**
 * WordPress Textdomain Registry object.
 *
 * Used to support just-in-time translations for manually loaded text domains.
 *
 * @since 6.1.0
 *
 * @global WP_Textdomain_Registry $wp_textdomain_registry WordPress Textdomain Registry.
 */
if ( class_exists( '\WP_Textdomain_Registry' ) ) {
	$GLOBALS['wp_textdomain_registry'] = new WP_Textdomain_Registry();
	if( method_exists( $GLOBALS['wp_textdomain_registry'], 'init' ) ) {
		// introduced in WP6.5
		$GLOBALS['wp_textdomain_registry']->init();
	}
}

// Load multisite-specific files.
if ( is_multisite() ) {
	pd_maybe_require( ABSPATH . WPINC . '/ms-functions.php' );
	pd_maybe_require( ABSPATH . WPINC . '/ms-default-filters.php' );
	pd_maybe_require( ABSPATH . WPINC . '/ms-deprecated.php' );
}

// Define constants that rely on the API to obtain the default value.
// Define must-use plugin directory constants, which may be overridden in the sunrise.php drop-in.
wp_plugin_directory_constants();

$GLOBALS['wp_plugin_paths'] = array();

// Load must-use plugins.
foreach ( wp_get_mu_plugins() as $mu_plugin ) {
	$_wp_plugin_file = $mu_plugin;
	include_once $mu_plugin;
	$mu_plugin = $_wp_plugin_file; // Avoid stomping of the $mu_plugin variable in a plugin.

	/**
	 * Fires once a single must-use plugin has loaded.
	 *
	 * @since 5.1.0
	 *
	 * @param string $mu_plugin Full path to the plugin's main file.
	 */
	do_action( 'mu_plugin_loaded', $mu_plugin );
}
unset( $mu_plugin, $_wp_plugin_file );

// Load network activated plugins.
if ( is_multisite() ) {
	foreach ( wp_get_active_network_plugins() as $network_plugin ) {
		wp_register_plugin_realpath( $network_plugin );
		include_once( $network_plugin );
	}
	unset( $network_plugin );
}

/**
 * Fires once all must-use and network-activated plugins have loaded.
 *
 * @since 2.8.0
 */
do_action( 'muplugins_loaded' );

if ( is_multisite() ) {
	ms_cookie_constants();
}

// Define constants after multisite is loaded.
wp_cookie_constants();

// Define and enforce our SSL constants
wp_ssl_constants();

// Create common globals.
pd_maybe_require( ABSPATH . WPINC . '/vars.php' );

// Make taxonomies and posts available to plugins and themes.
// @plugin authors: warning: these get registered again on the init hook.
create_initial_taxonomies();
create_initial_post_types();

if ( function_exists( 'wp_start_scraping_edited_file_errors' ) ) {
	wp_start_scraping_edited_file_errors();
}

// Register the default theme directory root
register_theme_directory( get_theme_root() );

/* PD: Start cache disable */

// Load active plugins.
// foreach ( wp_get_active_and_valid_plugins() as $plugin ) {
// 	wp_register_plugin_realpath( $plugin );
// 	include_once( $plugin );
// }
// unset( $plugin );

/* PD: End cache disable */

// Load pluggable functions.
pd_maybe_require( ABSPATH . WPINC . '/pluggable.php' );
pd_maybe_require( ABSPATH . WPINC . '/pluggable-deprecated.php' );

// Set internal encoding.
wp_set_internal_encoding();

// Run wp_cache_postload() if object cache is enabled and the function exists.
if ( WP_CACHE && function_exists( 'wp_cache_postload' ) ) {
	wp_cache_postload();
}
/**
 * Fires once activated plugins have loaded.
 *
 * Pluggable functions are also available at this point in the loading order.
 *
 * @since 1.5.0
 */
do_action( 'plugins_loaded' );

// Define constants which affect functionality if not already defined.
wp_functionality_constants();

// Add magic quotes and set up $_REQUEST ( $_GET + $_POST )
wp_magic_quotes();

/**
 * Fires when comment cookies are sanitized.
 *
 * @since 2.0.11
 */
do_action( 'sanitize_comment_cookies' );

/**
 * WordPress Query object
 * @global WP_Query $wp_the_query
 * @since 2.0.0
 */
$GLOBALS['wp_the_query'] = new WP_Query();

/**
 * Holds the reference to @see $wp_the_query
 * Use this global for WordPress queries
 * @global WP_Query $wp_query
 * @since 1.5.0
 */
$GLOBALS['wp_query'] = $GLOBALS['wp_the_query'];

/**
 * Holds the WordPress Rewrite object for creating pretty URLs
 * @global WP_Rewrite $wp_rewrite
 * @since 1.5.0
 */
$GLOBALS['wp_rewrite'] = new WP_Rewrite();

/**
 * WordPress Object
 * @global WP $wp
 * @since 2.0.0
 */
$GLOBALS['wp'] = new WP();

/**
 * WordPress Widget Factory Object
 * @global WP_Widget_Factory $wp_widget_factory
 * @since 2.8.0
 */
$GLOBALS['wp_widget_factory'] = new WP_Widget_Factory();

/**
 * WordPress User Roles
 * @global WP_Roles $wp_roles
 * @since 2.0.0
 */
$GLOBALS['wp_roles'] = new WP_Roles();

/**
 * Fires before the theme is loaded.
 *
 * @since 2.6.0
 */
do_action( 'setup_theme' );

// Define the template related constants.
wp_templating_constants();
if( function_exists( 'wp_set_template_globals' ) ) {
	// introduced in WP6.5
	wp_set_template_globals();
}

// Load the default text localization domain.
load_default_textdomain();

$locale = get_locale();
$locale_file = WP_LANG_DIR . "/$locale.php";
if ( ( 0 === validate_file( $locale ) ) && is_readable( $locale_file ) )
	require( $locale_file );
unset( $locale_file );

/**
 * WordPress Locale object for loading locale domain date and various strings.
 * @global WP_Locale $wp_locale
 * @since 2.1.0
 */
$GLOBALS['wp_locale'] = new WP_Locale();

/**
 *  WordPress Locale Switcher object for switching locales.
 *
 * @since 4.7.0
 *
 * @global WP_Locale_Switcher $wp_locale_switcher WordPress locale switcher object.
 */
$GLOBALS['wp_locale_switcher'] = new WP_Locale_Switcher();
$GLOBALS['wp_locale_switcher']->init();

// Load the functions for the active theme, for both parent and child theme if applicable.
if ( ! wp_installing() || 'wp-activate.php' === $pagenow ) {
	if ( TEMPLATEPATH !== STYLESHEETPATH && file_exists( STYLESHEETPATH . '/functions.php' ) )
		include( STYLESHEETPATH . '/functions.php' );
	if ( file_exists( TEMPLATEPATH . '/functions.php' ) )
		include( TEMPLATEPATH . '/functions.php' );
}
unset( $theme );

/**
 * Fires after the theme is loaded.
 *
 * @since 3.0.0
 */
do_action( 'after_setup_theme' );

// Create an instance of WP_Site_Health so that Cron events may fire.
if ( ! class_exists( 'WP_Site_Health' ) ) {
	require_once ABSPATH . 'wp-admin/includes/class-wp-site-health.php';
}
WP_Site_Health::get_instance();

// Set up current user.
$GLOBALS['wp']->init();

/**
 * Fires after WordPress has finished loading but before any headers are sent.
 *
 * Most of WP is loaded at this stage, and the user is authenticated. WP continues
 * to load on the {@see 'init'} hook that follows (e.g. widgets), and many plugins instantiate
 * themselves on it for all sorts of reasons (e.g. they need a user, a taxonomy, etc.).
 *
 * If you wish to plug an action once WP is loaded, use the {@see 'wp_loaded'} hook below.
 *
 * @since 1.5.0
 */
do_action( 'init' );

// Check site status
if ( is_multisite() ) {
	if ( true !== ( $file = ms_site_check() ) ) {
		require( $file );
		die();
	}
	unset($file);
}

/**
 * This hook is fired once WP, all plugins, and the theme are fully loaded and instantiated.
 *
 * Ajax requests should use wp-admin/admin-ajax.php. admin-ajax.php can handle requests for
 * users not logged in.
 *
 * @link https://developer.wordpress.org/plugins/javascript/ajax
 *
 * @since 3.0.0
 */
do_action( 'wp_loaded' );
