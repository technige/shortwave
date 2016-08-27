<?php
header('Content-Type: text/plain; charset=UTF-8');
$text = urldecode($_SERVER['QUERY_STRING']);
print($text);
?>
