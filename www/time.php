<?php
header('Content-Type: text/plain;charset=US-ASCII');
$format = $_SERVER['QUERY_STRING'];
if (strlen($format) == 0) {
	$format = 'c';
}
print(date($format));
?>
