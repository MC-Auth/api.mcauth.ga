<?php
function db()
{
    extract(json_decode(file_get_contents("../internal/mongo.json"), true));
    $auth = "";
    if (!is_null($login['user']) && !is_null($login['pass'])) {
        $auth = $login['user'] . ':' . $login['pass'] . '@';
    }
    try {
        $mongo = new MongoClient ('mongodb://' . $auth . $host . ':' . $port . '/' . $login['db']);
        $db = $mongo->selectDB($database);
    } catch (Exception $e) {
        http_response_code(500);
        exit("Database connection failed");
    }
    return $db;
}

//** Database **//
function dbToJson($cursor, $forceArray = false)
{
    $isArray = $cursor->count() > 1;
    $json = array();
    foreach ($cursor as $k => $row) {
        if ($isArray || $forceArray) {
            $json [] = $row;
        } else {
            return $row;
        }
    }
    return $json;
}

function accounts()
{
    $db = db();
    return $db->accounts;
}

function requests()
{
    $db = db();
    return $db->requests;
}

function oauth_requests()
{
    $db = db();
    return $db->oauth_requests;
}