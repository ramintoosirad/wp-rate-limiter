<?php
/**
 * Plugin Name:       VX Rate Limiter
 * Plugin URI:        https://github.com/ramintoosirad/wp-rate-limiter
 * Description:       Protects WordPress logins, forms and custom AJAX/REST endpoints from brute-force and scraping with per-IP sliding-window rate limits, IP allow/block lists and a lockout log.
 * Version:           1.0.0
 * Requires at least: 6.0
 * Requires PHP:      7.4
 * Author:            Vortaxis Studio
 * Author URI:        https://vortaxis.com
 * License:           GPL-2.0-or-later
 * Text Domain:       vx-rate-limiter
 */

defined( 'ABSPATH' ) || exit;

final class VX_Rate_Limiter {

	const OPTION = 'vx_rl_settings';
	const LOG    = 'vx_rl_log';

	public static function init() {
		add_filter( 'authenticate', array( __CLASS__, 'guard_login' ), 30, 3 );
		add_action( 'wp_login_failed', array( __CLASS__, 'record_login_failure' ) );
		add_filter( 'rest_pre_dispatch', array( __CLASS__, 'guard_rest' ), 10, 3 );
		add_action( 'admin_init', array( __CLASS__, 'guard_ajax' ), 1 );
		add_action( 'admin_menu', array( __CLASS__, 'menu' ) );
		add_action( 'admin_init', array( __CLASS__, 'register_settings' ) );
	}

	/* ---------------------------------------------------------------------
	 * Settings
	 * ------------------------------------------------------------------ */

	public static function defaults() {
		return array(
			'login_limit'   => '5/15',      // 5 failed logins per 15 minutes.
			'rest_limit'    => '60/1',      // 60 REST requests per minute.
			'ajax_actions'  => '',          // One "action=limit/minutes" per line, e.g. serial_lookup=3/1.
			'rest_routes'   => '',          // One "/namespace/route=limit/minutes" per line.
			'allowlist'     => '',
			'blocklist'     => '',
			'trust_proxy'   => 0,
		);
	}

	public static function settings() {
		return wp_parse_args( (array) get_option( self::OPTION, array() ), self::defaults() );
	}

	/** Parse "limit/minutes" into [limit, seconds]. */
	private static function parse_rule( $rule ) {
		if ( preg_match( '/^\s*(\d+)\s*\/\s*(\d+)\s*$/', (string) $rule, $m ) ) {
			return array( max( 1, (int) $m[1] ), max( 1, (int) $m[2] ) * MINUTE_IN_SECONDS );
		}
		return null;
	}

	/** Parse "key=limit/minutes" lines into [key => [limit, seconds]]. */
	private static function parse_map( $text ) {
		$map = array();
		foreach ( preg_split( '/\r\n|\r|\n/', (string) $text ) as $line ) {
			if ( strpos( $line, '=' ) === false ) {
				continue;
			}
			list( $key, $rule ) = array_map( 'trim', explode( '=', $line, 2 ) );
			$parsed = self::parse_rule( $rule );
			if ( $key !== '' && $parsed ) {
				$map[ $key ] = $parsed;
			}
		}
		return $map;
	}

	/* ---------------------------------------------------------------------
	 * Client IP & lists
	 * ------------------------------------------------------------------ */

	public static function client_ip() {
		$ip = $_SERVER['REMOTE_ADDR'] ?? '';
		// Only trust proxy headers when explicitly enabled (e.g. behind Cloudflare), otherwise they can be spoofed.
		if ( self::settings()['trust_proxy'] ) {
			foreach ( array( 'HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR' ) as $header ) {
				if ( ! empty( $_SERVER[ $header ] ) ) {
					$ip = trim( explode( ',', $_SERVER[ $header ] )[0] );
					break;
				}
			}
		}
		return filter_var( $ip, FILTER_VALIDATE_IP ) ? $ip : '0.0.0.0';
	}

	private static function list_contains( $list, $ip ) {
		foreach ( preg_split( '/[\s,]+/', (string) $list, -1, PREG_SPLIT_NO_EMPTY ) as $entry ) {
			if ( self::ip_in_range( $ip, $entry ) ) {
				return true;
			}
		}
		return false;
	}

	/** Supports exact IPs and IPv4 CIDR ranges (e.g. 203.0.113.0/24). */
	public static function ip_in_range( $ip, $range ) {
		if ( strpos( $range, '/' ) === false ) {
			return $ip === $range;
		}
		list( $subnet, $bits ) = explode( '/', $range, 2 );
		$ip_long     = ip2long( $ip );
		$subnet_long = ip2long( $subnet );
		if ( false === $ip_long || false === $subnet_long ) {
			return false;
		}
		$mask = -1 << ( 32 - (int) $bits );
		return ( $ip_long & $mask ) === ( $subnet_long & $mask );
	}

	/* ---------------------------------------------------------------------
	 * Core limiter (sliding window stored in transients / object cache)
	 * ------------------------------------------------------------------ */

	/**
	 * Registers a hit for $bucket and returns true when the request is allowed.
	 */
	public static function hit( $bucket, $limit, $window, $record = true ) {
		$ip = self::client_ip();
		$s  = self::settings();

		if ( self::list_contains( $s['blocklist'], $ip ) ) {
			return false;
		}
		if ( self::list_contains( $s['allowlist'], $ip ) ) {
			return true;
		}

		$key  = 'vx_rl_' . md5( $bucket . '|' . $ip );
		$now  = time();
		$hits = array_filter(
			(array) get_transient( $key ),
			static function ( $t ) use ( $now, $window ) {
				return $t > $now - $window;
			}
		);

		if ( count( $hits ) >= $limit ) {
			self::log( $ip, $bucket );
			return false;
		}

		if ( $record ) {
			$hits[] = $now;
			set_transient( $key, array_values( $hits ), $window );
		}
		return true;
	}

	private static function log( $ip, $bucket ) {
		$log   = (array) get_option( self::LOG, array() );
		$log[] = array( 'time' => current_time( 'mysql' ), 'ip' => $ip, 'bucket' => $bucket );
		update_option( self::LOG, array_slice( $log, -200 ), false );
	}

	private static function deny_json( $message ) {
		status_header( 429 );
		header( 'Retry-After: 60' );
		wp_send_json_error( array( 'message' => $message ), 429 );
	}

	/* ---------------------------------------------------------------------
	 * Guards
	 * ------------------------------------------------------------------ */

	public static function guard_login( $user, $username, $password ) {
		if ( empty( $username ) ) {
			return $user;
		}
		$rule = self::parse_rule( self::settings()['login_limit'] );
		// Check without recording; failures are recorded in record_login_failure().
		if ( $rule && ! self::hit( 'login', $rule[0], $rule[1], false ) ) {
			return new WP_Error( 'vx_rl_locked', __( '<strong>Too many failed login attempts.</strong> Please try again later.', 'vx-rate-limiter' ) );
		}
		return $user;
	}

	public static function record_login_failure() {
		$rule = self::parse_rule( self::settings()['login_limit'] );
		if ( $rule ) {
			self::hit( 'login', $rule[0], $rule[1] );
		}
	}

	public static function guard_ajax() {
		if ( ! wp_doing_ajax() || empty( $_REQUEST['action'] ) ) {
			return;
		}
		$action = sanitize_key( wp_unslash( $_REQUEST['action'] ) );
		$map    = self::parse_map( self::settings()['ajax_actions'] );
		if ( isset( $map[ $action ] ) && ! self::hit( 'ajax:' . $action, $map[ $action ][0], $map[ $action ][1] ) ) {
			self::deny_json( __( 'Too many requests. Please slow down and try again shortly.', 'vx-rate-limiter' ) );
		}
	}

	public static function guard_rest( $result, $server, $request ) {
		$route = $request->get_route();
		$s     = self::settings();
		$map   = self::parse_map( $s['rest_routes'] );

		foreach ( $map as $prefix => $rule ) {
			if ( strpos( $route, $prefix ) === 0 && ! self::hit( 'rest:' . $prefix, $rule[0], $rule[1] ) ) {
				return new WP_Error( 'vx_rl_too_many', __( 'Too many requests.', 'vx-rate-limiter' ), array( 'status' => 429 ) );
			}
		}

		$global = self::parse_rule( $s['rest_limit'] );
		if ( $global && ! is_user_logged_in() && ! self::hit( 'rest', $global[0], $global[1] ) ) {
			return new WP_Error( 'vx_rl_too_many', __( 'Too many requests.', 'vx-rate-limiter' ), array( 'status' => 429 ) );
		}
		return $result;
	}

	/* ---------------------------------------------------------------------
	 * Admin
	 * ------------------------------------------------------------------ */

	public static function menu() {
		add_options_page( 'Rate Limiter', 'Rate Limiter', 'manage_options', 'vx-rate-limiter', array( __CLASS__, 'render' ) );
	}

	public static function register_settings() {
		register_setting( 'vx_rl', self::OPTION, array( 'sanitize_callback' => array( __CLASS__, 'sanitize' ) ) );
	}

	public static function sanitize( $in ) {
		$rule = static function ( $v, $d ) {
			return preg_match( '/^\d+\/\d+$/', trim( (string) $v ) ) ? trim( $v ) : $d;
		};
		$d = self::defaults();
		return array(
			'login_limit'  => $rule( $in['login_limit'] ?? '', $d['login_limit'] ),
			'rest_limit'   => $rule( $in['rest_limit'] ?? '', $d['rest_limit'] ),
			'ajax_actions' => sanitize_textarea_field( $in['ajax_actions'] ?? '' ),
			'rest_routes'  => sanitize_textarea_field( $in['rest_routes'] ?? '' ),
			'allowlist'    => sanitize_textarea_field( $in['allowlist'] ?? '' ),
			'blocklist'    => sanitize_textarea_field( $in['blocklist'] ?? '' ),
			'trust_proxy'  => empty( $in['trust_proxy'] ) ? 0 : 1,
		);
	}

	public static function render() {
		$s   = self::settings();
		$o   = self::OPTION;
		$log = array_reverse( (array) get_option( self::LOG, array() ) );
		?>
		<div class="wrap">
			<h1>VX Rate Limiter</h1>
			<p>Your IP: <code><?php echo esc_html( self::client_ip() ); ?></code> — add it to the allowlist to avoid locking yourself out.</p>
			<form method="post" action="options.php">
				<?php settings_fields( 'vx_rl' ); ?>
				<table class="form-table" role="presentation">
					<tr><th>Failed logins</th><td><input name="<?php echo esc_attr( $o ); ?>[login_limit]" value="<?php echo esc_attr( $s['login_limit'] ); ?>"> <span class="description">attempts / minutes, e.g. <code>5/15</code></span></td></tr>
					<tr><th>REST API (guests)</th><td><input name="<?php echo esc_attr( $o ); ?>[rest_limit]" value="<?php echo esc_attr( $s['rest_limit'] ); ?>"> <span class="description">requests / minutes</span></td></tr>
					<tr><th>AJAX actions</th><td><textarea class="large-text code" rows="4" name="<?php echo esc_attr( $o ); ?>[ajax_actions]" placeholder="serial_lookup=3/1"><?php echo esc_textarea( $s['ajax_actions'] ); ?></textarea><p class="description">One per line: <code>action=limit/minutes</code></p></td></tr>
					<tr><th>REST routes</th><td><textarea class="large-text code" rows="4" name="<?php echo esc_attr( $o ); ?>[rest_routes]" placeholder="/myplugin/v1/lookup=10/60"><?php echo esc_textarea( $s['rest_routes'] ); ?></textarea><p class="description">One per line: <code>/route-prefix=limit/minutes</code></p></td></tr>
					<tr><th>Allowlist</th><td><textarea class="large-text code" rows="3" name="<?php echo esc_attr( $o ); ?>[allowlist]"><?php echo esc_textarea( $s['allowlist'] ); ?></textarea><p class="description">IPs or CIDR ranges that are never limited.</p></td></tr>
					<tr><th>Blocklist</th><td><textarea class="large-text code" rows="3" name="<?php echo esc_attr( $o ); ?>[blocklist]"><?php echo esc_textarea( $s['blocklist'] ); ?></textarea><p class="description">IPs or CIDR ranges that are always blocked.</p></td></tr>
					<tr><th>Behind a proxy / Cloudflare</th><td><label><input type="checkbox" name="<?php echo esc_attr( $o ); ?>[trust_proxy]" value="1" <?php checked( $s['trust_proxy'] ); ?>> Trust <code>CF-Connecting-IP</code> / <code>X-Forwarded-For</code></label></td></tr>
				</table>
				<?php submit_button(); ?>
			</form>
			<h2>Recent lockouts</h2>
			<table class="widefat striped"><thead><tr><th>Time</th><th>IP</th><th>Rule</th></tr></thead><tbody>
				<?php if ( ! $log ) : ?><tr><td colspan="3">No lockouts yet.</td></tr><?php endif; ?>
				<?php foreach ( array_slice( $log, 0, 50 ) as $row ) : ?>
					<tr><td><?php echo esc_html( $row['time'] ); ?></td><td><?php echo esc_html( $row['ip'] ); ?></td><td><code><?php echo esc_html( $row['bucket'] ); ?></code></td></tr>
				<?php endforeach; ?>
			</tbody></table>
		</div>
		<?php
	}
}

VX_Rate_Limiter::init();
