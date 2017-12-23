<?php

global $config;

require_once('gpg-policy.inc.php');

get_config();

switch($config['command']):
case GPG_POLICY_CMD:
	header('Content-type: text/html; charset=UTF-8');
	policy_header();
	if (isset($config['policy'])):
		$policyFile = validate_file(join('.', array(GPG_Policy_Prefix, $config['policy'])));
	endif;
	if (isset($policyFile)): 
		policy_wrapper($policyFile);
		download_sidebar();
	else:
		policy_error("Not a valid GNU Privacy Guard policy URL");
	endif;
	policy_footer();
	break;
case GPG_SIG_CMD:
	if (isset($config['policy']) && isset($config['keyid'])):
		$signatureFile = validate_file(join('.', 
			array(GPG_Policy_Prefix, $config['policy'], $config['keyid'], GPG_Sig_Suffix)));
	endif;
	if (isset($config['policy'])):
		$policyFile = validate_file(join('.', array(GPG_Policy_Prefix, $config['policy'])));
		if (!isset($policyFile)):
			unset($config['policy']);
		endif;
	endif;
	if (isset($signatureFile) && isset($policyFile)):
		download_file($signatureFile, download_filename());
	else:
		policy_header();
		process_download_error();
		policy_footer();
	endif;
	break;
case GPG_CSIG_CMD:
	if (isset($config['policy'])):
		$signatureFile = validate_file(join('.', 
			array(GPG_Policy_Prefix, $config['policy'], GPG_Sig_Suffix)));
		$policyFile = validate_file(join('.', 
			array(GPG_Policy_Prefix, $config['policy'])));
		if (!isset($policyFile)):
			unset($config['policy']);
		endif;
	endif;
	if (isset($signatureFile) && isset($policyFile)):
		download_file($signatureFile, download_filename());
	else:
		policy_header();
		process_download_error();
		policy_footer();
	endif;
	break;
case GPG_DL_CMD:
	if (isset($config['policy'])):
		$policyFile = validate_file(join('.', array(GPG_Policy_Prefix, $config['policy'])));
	endif;
	if (isset($policyFile)):
		download_file($policyFile, download_filename());
	else:
		policy_header();
		process_download_error();
		policy_footer();
	endif;
	break;
default:
	$current = get_current();
	if (isset($current)):
		header('HTTP/1.1 301 Moved Permanently');
		header('Location: ' . join('/', array($config['baseurl'], 
			$config['script'], GPG_POLICY_CMD, $current)));
	else:
		policy_header();
		policy_error("No published policy");
		policy_footer();
	endif;
endswitch;
?>
