<?php
$code = $_SERVER['QUERY_STRING'];
if (strlen($code) == 0) {
	http_response_code($code);
} elseif (strlen($code) == 3) {
	http_response_code($code);
} else {
	$code = urldecode($code);
	header("HTTP/1.1 $code");
}
header('Content-Type: text/plain; charset=UTF-8');
?>
