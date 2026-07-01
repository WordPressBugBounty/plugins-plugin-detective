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

	public static function create_nonce( $action, $uid = null ) {
		if ( null === $uid ) {
			$uid = get_current_user_id();
		}
		$uid = (int) $uid;

		if ( ! empty( $_SERVER['HTTP_USER_AGENT'] ) ) {
			$token = sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) );
		} else {
			$token = '';
		}
		$i = strtotime( gmdate( 'Y-m-d' ) );

		// Bind the token to the user it was issued for so a low-privileged user's
		// nonce can never stand in for an administrator's. The uid travels with the
		// token (the app treats it as opaque) and is re-verified on each request.
		return $uid . ':' . substr( sha1( DB_PASSWORD . $i . '|' . $action . '|' . $uid . '|' . $token  ), -12, 10 );
	}

	public static function verify_nonce( $nonce, $action ) {
		$nonce = (string) $nonce;
		if ( empty( $nonce ) ) {
			return false;
		}

		// Tokens are "<uid>:<hash>" — recover the uid so the hash is checked against
		// the user it was minted for. Returns that uid on success for the caller's
		// capability re-check; false otherwise.
		$parts = explode( ':', $nonce, 2 );
		if ( count( $parts ) !== 2 || '' === $parts[1] ) {
			return false;
		}
		$uid = (int) $parts[0];
		$provided = $parts[1];

		if ( ! empty( $_SERVER['HTTP_USER_AGENT'] ) ) {
			$token = sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) );
		} else {
			$token = '';
		}

		$i = strtotime( gmdate( 'Y-m-d' ) );

		// Nonce generated today (gmt)
		$expected = substr( sha1( DB_PASSWORD . $i . '|' . $action . '|' . $uid . '|' . $token ), -12, 10 );
		if ( hash_equals( $expected, $provided ) ) {
			return $uid;
		}

		// Nonce generated yesterday (gmt)
		$expected = substr( sha1( DB_PASSWORD . ( $i - 24*60*60 ) . '|' . $action . '|' . $uid . '|' . $token  ), -12, 10 );
		if ( hash_equals( $expected, $provided ) ) {
			return $uid;
		}

		// Invalid nonce
		return false;
	}

}
