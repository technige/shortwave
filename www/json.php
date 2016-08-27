<?php
header('Content-Type: application/json; charset=UTF-8');
print(json_encode(array('method' => $_SERVER['REQUEST_METHOD'], 'query' => $_SERVER['QUERY_STRING'], 'content' => file_get_contents('php://input'))));
?>
