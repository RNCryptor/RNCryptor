<?php
error_reporting(E_ALL | E_STRICT);

if (!function_exists('hex2bin')) {

	/**
	 * If the PHP version being used is earlier than 5.4.0, we need to
	 * make up for the lack of a hex2bin() function.
	 */
	function hex2bin($data) {
		$bin = '';
		foreach (str_split($data, 2) as $pair) {
			$bin .= chr(hexdec($pair));
		}
		return $bin;
	}
}
