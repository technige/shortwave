<?php

$method = $_SERVER['REQUEST_METHOD'];
$parts = explode('/', $_SERVER['PATH_INFO']);
$collection = $parts[1];
$element = $parts[2];

$data = array(
    'request' => array(
        'method' => $method,
        'collection' => $collection,
        'time' => date('c'),
    ),
);

if ($element != '') {
    $data['request']['element'] = $element;
}

switch ($method) {
case 'GET':
    if ($element == '') {
        $data["{$collection}_collection"] = array('a', 'b', 'c');
    }
    else {
        $data["{$collection}"] = array(
            'name' => $element,
            'size' => rand(1, 40),
        );
    }
    http_response_code(200);
    break;
case 'PUT':
    http_response_code(200);
    break;
case 'POST':
    http_response_code(201);
    break;
case 'DELETE':
    http_response_code(200);
    break;
default:
    http_response_code(405);
    exit();
}

header('Content-Type: application/json;charset=UTF-8');
print(json_encode($data, JSON_PRETTY_PRINT));
print("\n");
    
?>
