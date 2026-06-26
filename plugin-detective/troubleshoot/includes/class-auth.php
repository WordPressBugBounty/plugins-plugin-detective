<?php
/**
 * Troubleshoot Auth.
 *
 * @since   0.0.0
 * @package Troubleshoot
 */

/**
 * Troubleshoot Auth.
 *
 * @since 0.0.0
 */
class PDT_Auth {
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

	/**
	 * Authenticate a username/password and require plugin-management capability.
	 *
	 * Every failure mode — unknown username, wrong password, or a valid login
	 * that lacks the activate_plugins capability — returns the SAME generic
	 * error. Distinct codes/messages here would let an unauthenticated caller
	 * probe which usernames exist (user enumeration), so they are deliberately
	 * collapsed into one indistinguishable response.
	 *
	 * @since  0.0.0
	 *
	 * @param  string $username Raw username input.
	 * @param  string $password Raw password input.
	 * @return WP_User|WP_Error Plugin-capable user on success, or one generic error.
	 */
	public static function authenticate( $username, $password ) {
		$username = sanitize_user( $username );
		$password = trim( $password );

		$user = apply_filters( 'authenticate', null, $username, $password );

		if ( ! is_a( $user, 'WP_User' ) || ! user_can( $user, 'activate_plugins' ) ) {
			return new WP_Error( 'authentication_failed', __( '<strong>ERROR</strong>: Authentication failed.', 'plugin-detective' ) );
		}

		return $user;
	}

	public static function create_nonce( $action ) {
		$uid = 'api';

		if ( ! empty( $_SERVER['HTTP_USER_AGENT'] ) ) {
			$token = sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) );
		} else {
			$token = '';
		}
		$i = strtotime( gmdate( 'Y-m-d' ) );

		return substr( sha1( DB_PASSWORD . $i . '|' . $action . '|' . $uid . '|' . $token  ), -12, 10 );	
	}

	public static function verify_nonce( $nonce, $action ) {
		$nonce = (string) $nonce;
		$uid = 'api';
		if ( ! empty( $_SERVER['HTTP_USER_AGENT'] ) ) {
			$token = sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) );
		} else {
			$token = '';
		}

		if ( empty( $nonce ) ) {
			return false;
		}

		$i = strtotime( gmdate( 'Y-m-d' ) );

		// Nonce generated today (gmt)
		$expected = substr( sha1( DB_PASSWORD . $i . '|' . $action . '|' . $uid . '|' . $token ), -12, 10 );
		if ( hash_equals( $expected, $nonce ) ) {
			return 1;
		}

		// Nonce generated yesterday (gmt)
		$expected = substr( sha1( DB_PASSWORD . ( $i - 24*60*60 ) . '|' . $action . '|' . $uid . '|' . $token  ), -12, 10 );
		if ( hash_equals( $expected, $nonce ) ) {
			return 2;
		}

		// Invalid nonce
		return false;
	}

}
