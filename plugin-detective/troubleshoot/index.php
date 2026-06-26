<?php
// define( 'WP_DEBUG', false );
// ini_set( 'display_errors', false );
require_once dirname( __FILE__ ) . '/troubleshoot.php';
$app = pd_troubleshoot();

// check if we're attempting to restore the site
// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Emergency restore link; delete_maintenance_file() enforces an is_user_logged_in() + manage_options capability check before acting.
if ( isset( $_GET['restore'] ) ) {
	if ( $app->delete_maintenance_file() ) {
		wp_safe_redirect( home_url() );
		exit;
	}
}


?>
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Plugin Detective</title>
		<?php // phpcs:disable WordPress.WP.EnqueuedResources.NonEnqueuedStylesheet -- Standalone troubleshooter page rendered outside WordPress; wp_enqueue_style()/wp_head() are unavailable here. ?>
		<link rel="stylesheet" href="//fonts.googleapis.com/css?family=Roboto:300,400,500,700,400italic">
		<link rel="stylesheet" href="//fonts.googleapis.com/icon?family=Material+Icons">
		<link href="<?php echo esc_url( $app->url( 'app/dist/static/css/app.css' ) ); ?>" rel="stylesheet">
		<?php // phpcs:enable WordPress.WP.EnqueuedResources.NonEnqueuedStylesheet ?>
  </head>
  <body>
    <div id="app"></div>

	<script type='text/javascript'>
    var app = <?php echo json_encode( $app->get_api_params() ); ?>;
    var pd_translations = <?php echo json_encode( $app->get_translations() ); ?>;
	</script>
		<?php // phpcs:disable WordPress.WP.EnqueuedResources.NonEnqueuedScript -- Standalone troubleshooter page rendered outside WordPress; wp_enqueue_script()/wp_footer() are unavailable here. ?>
    <script type=text/javascript src="<?php echo esc_url( $app->url( 'app/dist/static/js/manifest.js' ) . '?v=' . PD_Troubleshoot::VERSION ); ?>"></script>
    <script type=text/javascript src="<?php echo esc_url( $app->url( 'app/dist/static/js/chunk-vendors.js' ) . '?v=' . PD_Troubleshoot::VERSION ); ?>"></script>
    <script type=text/javascript src="<?php echo esc_url( $app->url( 'app/dist/static/js/app.js' ) . '?v=' . PD_Troubleshoot::VERSION ); ?>"></script>
		<?php // phpcs:enable WordPress.WP.EnqueuedResources.NonEnqueuedScript ?>
  </body>
</html>
