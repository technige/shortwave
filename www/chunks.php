<?php
header('Content-Type: text/plain');
$count = $_SERVER['QUERY_STRING'];
if ($count == '') {
	$count = 5;
}
$count = (int) $count;
flush();
ob_flush();
sleep(1);
for ($i = 1; $i <= $count; $i++) {
	print(decbin($i));
	flush();
	ob_flush();
	sleep(1);
}
?>
