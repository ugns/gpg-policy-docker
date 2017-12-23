<?php

require_once('gpg-config.inc.php');

define('GPG_Data_PATH', join(DIRECTORY_SEPARATOR,
	array(GPG_Policy_DIR, GPG_Data_DIR)));

define('GPG_POLICY_CMD', 'policy');
define('GPG_DL_CMD', 'download');
define('GPG_CSIG_CMD', 'signed');
define('GPG_SIG_CMD', 'signature');

define('GPG_CURRENT', 'current');
define('GPG_ASC_Suffix', 'asc');
define('GPG_LIC_FILE', 'gpg-policy.lic.php');

define('GPG_APP_VER_MAJOR', 0);
define('GPG_APP_VER_MINOR', 3);
define('GPG_APP_VER_PATCH', 1);

define('GPG_AUTHOR_NAME', 'Jeremy T. Bouse');
define('GPG_COPY_YEAR', '2009-2018');
define('GPG_COPY_HOLDER', 'UnderGrid Network Services');

define('GPG_AUTHOR_CREDIT', 'Designed by %1$s');
define('GPG_APP_TITLE', 'GnuPG Key Policy Manager v%1$s (%2$s)');
define('GPG_APP_COPYRIGHT', 'Copyright &#169; %1$s %2$s');

$licenseFile = join(DIRECTORY_SEPARATOR, array(GPG_Data_PATH, GPG_LIC_FILE));
if (file_exists($licenseFile)):
	include_once($licenseFile);
endif;

function get_version() {
  return join ('.', array(GPG_APP_VER_MAJOR, GPG_APP_VER_MINOR, GPG_APP_VER_PATCH));
}

function get_licensee() {
	if (function_exists('valid_gpg_license') && GpG_L1c3Ns3_F1l3):
 		if (valid_gpg_license()):
			return license_details();
		else:
			return 'Invalid license';
		endif;
	else:
		return 'Shareware';
	endif;
}

function get_config() {
	global $config;

	$policy = array (
		1 => array('policy'),
		array('policy', 'checksum'),
	);
	$download = array(
		1 => array('policy'),
	);
	$clearsign = array(
		1 => array('policy'),
	);
	$signature = array(
		1 => array('policy'),
		array('policy','keyid'),
	);

	if (isset($_SERVER['PATH_INFO'])):
		$path = explode('/', $_SERVER['PATH_INFO']);
		array_shift($path); // get rid of empty element
		$cmd = $path[0];
		array_shift($path); // remove command from
		switch($cmd):
			case GPG_POLICY_CMD:
				if (isset($policy[count($path)])):
					$config = array_combine($policy[count($path)], $path);
				endif;
				break;
			case GPG_SIG_CMD:
				if (isset($signature[count($path)])):
					$config = array_combine($signature[count($path)], $path);
				endif;
				break;
			case GPG_CSIG_CMD:
				if (isset($clearsign[count($path)])):
					$config = array_combine($clearsign[count($path)], $path);
				endif;
				break;
			case GPG_DL_CMD:
				if (isset($download[count($path)])):
					$config = array_combine($download[count($path)], $path);
				endif;
				break;
		endswitch;

		if (isset($config['policy']) && !preg_match('/[0-9]{8}/', $config['policy'])):
			unset($config['policy']);
		endif;

		if (isset($config['keyid']) && preg_match('/[0-9A-Fa-f]{16}/', $config['keyid'])):
			$config['keyid'] = strtoupper(substr($config['keyid'],8,8));
		elseif (isset($config['keyid']) && preg_match('/[0-9A-Fa-f]{8}/', $config['keyid'])):
			$config['keyid'] = strtoupper($config['keyid']);
		else:
			unset($config['keyid']);
		endif;
	endif;

	$refs = pathinfo($_SERVER['SCRIPT_NAME']);

	if (strlen($refs['dirname']) > 1):
		$config['baseurl'] = $refs['dirname'];
	else:
		$config['baseurl'] = '';
	endif;
	if (isset($refs['filename'])):
		$config['script'] = $refs['filename'];
	else:
		$config['script'] = basename($refs['basename'], '.'.$refs['extension']);
	endif;
	if (isset($cmd)):
		$config['command'] = $cmd;
	else:
		$config['command'] = '';
	endif;
}

function get_current() {
	$currentFile = validate_file(GPG_CURRENT);
	if (isset($currentFile)):
		$current = file_get_contents(join (DIRECTORY_SEPARATOR, array(GPG_Data_PATH, $currentFile)));
		return $current;
	else:
		if ($dh = opendir(GPG_Data_PATH)):
			$pattern = join('\.', array(GPG_Policy_Prefix, '([0-9]{8})'));
			while (($file = readdir($dh)) != false):
				if(preg_match('/^'.$pattern.'$/', $file, $matches)):
					$policies[] = $matches[1];
				endif;
			endwhile;
		endif;
		asort($policies);
		return array_pop($policies);
	endif;
}

function command_uri($command) {
	global $config;

	return join('/', array(
		$config['baseurl'],
		$config['script'],
		$command,
		$config['policy']));
}

function download_filename() {
	global $config;

	switch($config['command']):
		case GPG_DL_CMD:
			return join('-', array(
				'gpg',
				GPG_Policy_Prefix,
				$config['policy']));
			break;
		case GPG_CSIG_CMD:
			return join('.', array(
				join('-', array(
					'gpg',
					GPG_Policy_Prefix,
					$config['policy'])),
				GPG_ASC_Suffix));
			break;
		case GPG_SIG_CMD:
			return join('.', array(
				join('-', array(
					'gpg',
					GPG_Policy_Prefix,
					$config['policy'],
					$config['keyid'])),
				GPG_ASC_Suffix));
			break;
	endswitch;
}

function download_file($filename, $attachment) {
	header('Content-type: text/plain');
	header('Content-Disposition: attachment; filename=' . $attachment);
	readfile (join (DIRECTORY_SEPARATOR, array(GPG_Data_PATH, $filename)));
}

function validate_file($filename) {
	$filename = basename($filename);
	$tmpFilename = join (DIRECTORY_SEPARATOR, array(GPG_Data_PATH, $filename));

	if (file_exists($tmpFilename)):
		return $filename;
	endif;
}

function validate_Xsum($algo, $checksum, $filename) {
	if (hash_file($algo, join (DIRECTORY_SEPARATOR, array(GPG_Data_PATH, $filename))) == $checksum):
	?>
	<div class="chksum good">
		<h2><?= strtoupper($algo); ?> Checksum verified</h2>
	</div>
	<?php
	else:
	?>
	<div class="chksum bad">
		<h2><?= strtoupper($algo); ?> Checksum NOT valid</h2>
	</div>
	<?php
	endif;
}

function validate_checksum($checksum, $filename) {
	if (strlen($checksum) == 32):
		validate_Xsum('md5', $checksum, $filename);
	elseif (strlen($checksum) == 40):
		validate_Xsum('sha1', $checksum, $filename);
	elseif (strlen($checksum) == 64):
		validate_Xsum('sha256', $checksum, $filename);
	else:
		?>
		<div class="chksum bad">
			<h2>No valid checksum provided</h2>
		</div>
		<?php
	endif;
}

function provide_checksums($filename) {
	global $config;

	$md5sum = hash_file('md5', join (DIRECTORY_SEPARATOR,
		array(GPG_Data_PATH, $filename)));
	$sha1sum = hash_file('sha1', join (DIRECTORY_SEPARATOR,
		array(GPG_Data_PATH, $filename)));
	$sha256sum = hash_file('sha256', join (DIRECTORY_SEPARATOR,
		array(GPG_Data_PATH, $filename)));

	?>
	<div class="chksum good">
		<p>MD5 Checksum <a href="<?=
			join('/', array(command_uri(GPG_POLICY_CMD), $md5sum)); ?>"><?= $md5sum; ?></a></p>
		<p>SHA1 Checksum <a href="<?=
			join('/', array(command_uri(GPG_POLICY_CMD), $sha1sum)); ?>"><?= $sha1sum; ?></a></p>
		<p>SHA256 Checksum <a href="<?=
			join('/', array(command_uri(GPG_POLICY_CMD), $sha256sum)); ?>"><?= $sha256sum; ?></a></p>
	</div>
	<?php
}

function policy_error($message) {
	?>
	<div class="error bad">
		<h1><?= $message; ?></h1>
	</div>
	<?php
}

function process_download_error() {
  global $config;

	switch($config['command']):
		case GPG_CSIG_CMD:
			if (!isset($config['policy'])):
				policy_error("Not a valid policy signature");
				break;
			elseif (isset($config['policy'])):
				policy_error("That policy signature can not be found");
				break;
			endif;
		case GPG_SIG_CMD:
			if (!isset($config['keyid']) && !isset($config['policy'])):
				policy_error("Not a valid policy or key ID");
			elseif (!isset($config['keyid']) && isset($config['policy'])):
				policy_error("Invalid signature key ID for this policy");
			elseif (isset($config['keyid']) && !isset($config['policy'])):
				policy_error("The policy for that signature can not be found");
			else:
				policy_error("Invalid signature key ID");
			endif;
				break;
		default:
			if (!isset($config['policy'])):
				policy_error("Invalid policy URL");
				break;
			elseif (isset($config['policy'])):
				policy_error("That policy can not be found");
				break;
			endif;
	endswitch;
}

function policy_header() {
  global $config;

	?>
	<html>
	<head>
		<title><?= GPG_Owner_Name ?> GNU Privacy Guard Key Policy</title>
		<link href="<?= $config['baseurl']; ?>/gpg-policy.css" rel="stylesheet" type="text/css" />
		<link href="<?= $config['baseurl']; ?>/gnupg-icon.png" type="image/png" rel="icon" />
	</head>
	<body>
	<?php
}

function policy_footer() {
	global $config;

	?>
	<div class="footer credits">
	<?= sprintf(GPG_APP_TITLE, get_version(), get_licensee()); ?> <br />
	<?= sprintf(GPG_AUTHOR_CREDIT, GPG_AUTHOR_NAME); ?> - <?=		sprintf(GPG_APP_COPYRIGHT, GPG_COPY_YEAR, GPG_COPY_HOLDER); ?>
	</div>
	</body>
	</html>
	<?php
}

function policy_link($text, $url) {
	?><a href="<?= $url; ?>"><?= $text; ?></a><?php
}

function policy_display($filename) {
	?>
		<div class=policy>
			<pre>
	<?= htmlentities(file_get_contents(join ('/', array(GPG_Data_PATH, $filename)))); ?>
			</pre>
		</div>
	<?php
}

function policy_wrapper($filename) {
	global $config;

	?>
	<div class=wrapper>
	<?php
		if (isset($config['checksum'])):
			validate_checksum($config['checksum'], $filename);
		else:
			provide_checksums($filename);
		endif;

		policy_display($filename);
	?>
	</div>
	<?php
}

function download_sidebar() {
  global $config;

	?>
	<div class=download>
		<h3>Related links</h3>
		<ul>
			<li><?php policy_link('Raw policy file', command_uri(GPG_DL_CMD)); ?></li>
	<?php
		if ($dh = opendir(GPG_Data_PATH)):
			$pattern = join('\.', array(GPG_Policy_Prefix, $config['policy'], '(\w+)', GPG_Sig_Suffix));
			$cspattern = join('\.', array(GPG_Policy_Prefix, $config['policy'], GPG_Sig_Suffix));
			while (($file = readdir($dh)) != false):
				if(preg_match('/^'.$pattern.'$/', $file, $matches)):
	?>
			<li><?php policy_link('0x' . $matches[1] . ' sig',
				join('/', array(command_uri(GPG_SIG_CMD), $matches[1]))); ?></li>
	<?php
				elseif(preg_match('/^'.$cspattern.'$/', $file, $matches)):
	?>
			<li><?php policy_link('Clearsigned sig',
				join('/', array(command_uri(GPG_CSIG_CMD)))); ?></li>
	<?php
				endif;
			endwhile;
		endif;
	?>
		</ul>
	</div>
	<?php
}

if (!function_exists('array_combine')) {
	function array_combine($arr1, $arr2) {
		$out = array();
		$arr1 = array_values($arr1);
		$arr2 = array_values($arr2);
		foreach($arr1 as $key1 => $value1) {
			$out[(string)$value1] = $arr2[$key1];
		}
		return $out;
	}
}

?>
