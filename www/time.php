<?php
header('Content-Type: text/plain; charset=UTF-8');
$format = $_SERVER['QUERY_STRING'];
if (strlen($format) == 0) {
	$format = 'c';
}
print(date($format));
?>
