<?php
session_start();

require "../vendor/autoload.php";
include("../internal/Database.php");

$app = new Slim\Slim();
$app->notFound(function () use ($app) {
    echoData(array("error" => "invalid route"));
});


$app->hook("slim.before", function () use ($app) {
    header("Access-Control-Allow-Origin: https://mcauth.ga");
    header("Access-Control-Allow-Credentials: true");
    if ($_SERVER["REQUEST_METHOD"] === "OPTIONS") {
        header("Access-Control-Allow-Methods: POST, GET, OPTIONS, DELETE, PUT");
        header("Access-Control-Allow-Headers: X-Requested-With, Accept, Content-Type, Origin");
        header("Access-Control-Request-Headers: X-Requested-With, Accept, Content-Type, Origin");
        exit;
    }
});

$app->group("/auth", function () use ($app) {

    // 1. Request (API)
    $app->post("/start", function () use ($app) {
        $requestId = getParam($app, "request_id");// public
        $secret = getParam($app, "request_secret");// secret
        $callback = getParam($app, "request_callback");// secret
        $ip = getParam($app, "request_ip");// public
        $username = getParam($app, "username");// public

        $existingRequest = requests()->find(array("request_id" => $requestId));
        if ($existingRequest->count() > 0) {
            echoData(array("error" => "Request with this ID already exists"), 400);
            exit();
        }

        $existingRequest = requests()->find(array("username" => $username, "request_ip" => $ip, "status" => array('$in' => array("STARTED", "REQUESTED"))));
        if ($existingRequest->count() > 0) {
            echoData(array("error" => "Request with this IP <-> Username combination already exists"), 400);
            exit();
        }

        if (checkUsername($app, $username) === false) {
            echoData(array("error" => "Invalid username"), 400);
            exit();
        }

        $id = hash("sha1", microtime(true) . $ip . rand() . $requestId . rand());
        $code = hash("sha256", microtime(true) . $requestId . rand() . $ip . rand() . $username . rand() . $secret);

        requests()->insert(array(
            "_id" => $id,
            "code" => $code,
            "request_id" => $requestId,
            "request_secret" => $secret,
            "request_callback" => $callback,
            "request_ip" => $ip,
            "username" => $username,
            "status" => "STARTED",
            "created" => new MongoDate(time())
        ));

        echoData(array(
            "msg" => "Authentication requested",
            "id" => $id,// public
            "code" => $code,// secret
            "request_id" => $requestId,// public
            "username" => $username,// public
            "ip" => $ip,// public
            "status" => "STARTED"
        ));
    });

    // 2. Request (redirect)
    $app->get("/authorize/:id", function ($id) use ($app) {
        $requestId = getParam($app, "request_id");// public
        $username = getParam($app, "username");// public
        $style = $app->request()->params("style", "default");// public (default|simple)
        $ip = $app->request()->getIp();

        $request = requests()->find(array(
            "_id" => $id));
        if ($request->count() == 0) {
            echoData(array("error" => "Request not found"), 404);
            exit();
        }
        $request = dbToJson($request);

        if ($request["request_id"] !== $requestId) {
            echoData(array("error" => "Request ID mismatch"), 400);
            exit();
        }
        if ($request["username"] !== $username) {
            echoData(array("error" => "Username mismatch"), 400);
            exit();
        }
        if ($request["request_ip"] !== $ip) {
            echoData(array("error" => "IP mismatch ($ip)"), 400);
            exit();
        }

        setcookie("mcauth_id", base64_encode($id), time() + 600, "/", "mcauth.ga");
        setcookie("mcauth_request_id", base64_encode($requestId), time() + 600, "/", "mcauth.ga");
        setcookie("mcauth_username", base64_encode($username), time() + 600, "/", "mcauth.ga");
        setcookie("mcauth_style", $style, time() + 600, "/", "mcauth.ga");

        $_SESSION["auth_id"] = $id;
        $_SESSION["auth_request_id"] = $requestId;
        $_SESSION["auth_username"] = $username;
        $_SESSION["auth_style"] = $style;

        // update status
        requests()->update(array("_id" => $id), array('$set' => array("status" => "REQUESTED")));

        header("Location: https://mcauth.ga/#/auth");
        exit();
    });

    $app->group("/api", function () use ($app) {

        $app->get("/check/:id", function ($id) use ($app) {
            $request = requests()->find(array(
                "_id" => $id));
            if ($request->count() == 0) {
                echoData(array("error" => "Request not found"), 404);
                exit();
            }
            $request = dbToJson($request);

            if ($request["_id"] !== $_SESSION["auth_id"]) {
                echoData(array("error" => "Session ID mismatch"), 400);
                exit();
            }
            if ($request["request_id"] !== $_SESSION["auth_request_id"]) {
                echoData(array("error" => "Session Request ID mismatch"), 400);
                exit();
            }
            if ($request["username"] !== $_SESSION["auth_username"]) {
                echoData(array("error" => "Session Username mismatch"), 400);
                exit();
            }

            $created = $request["created"]->sec;
            if ((time() - $created) > 300) {
                requests()->update(array("_id" => $id), array('$set' => array("status" => "TIMEOUT_LOGIN")));
                $request["status"] = "TIMEOUT_LOGIN";
            }
            echoData(array(
                "id" => $id,
                "status" => $request["status"],
                "created" => $created
            ));
        });

        $app->get("/verify/:id", function ($id) use ($app) {
            $token = getParam($app, "token");

            $request = requests()->find(array(
                "_id" => $id));
            if ($request->count() == 0) {
                echoData(array("error" => "Request not found"), 404);
                exit();
            }
            $request = dbToJson($request);

            if ($request["_id"] !== $_SESSION["auth_id"]) {
                echoData(array("error" => "Session ID mismatch"), 400);
                exit();
            }
            if ($request["request_id"] !== $_SESSION["auth_request_id"]) {
                echoData(array("error" => "Session Request ID mismatch"), 400);
                exit();
            }
            if ($request["username"] !== $_SESSION["auth_username"]) {
                echoData(array("error" => "Session Username mismatch"), 400);
                exit();
            }

            if (!isset($request["token"]) || ($request["token"] !== $token)) {
                requests()->update(array("_id" => $id), array('$set' => array("status" => "INVALID_TOKEN")));
                echoData(array(
                    "id" => $id,
                    "status" => "INVALID_TOKEN"
                ));
                exit();
            } else {
                requests()->update(array("_id" => $id), array('$set' => array("status" => "VERIFIED")));
                echoData(array(
                    "id" => $id,
                    "status" => "VERIFIED"
                ));
            }
        });

    });

    $app->get("/finish/:id", function ($id) use ($app) {
        $request = requests()->find(array(
            "_id" => $id));
        if ($request->count() == 0) {
            echoData(array("error" => "Request not found"), 404);
            exit();
        }
        $request = dbToJson($request);

        if ($request["_id"] !== $_SESSION["auth_id"]) {
            echoData(array("error" => "Session ID mismatch"), 400);
            exit();
        }
        if ($request["request_id"] !== $_SESSION["auth_request_id"]) {
            echoData(array("error" => "Session Request ID mismatch"), 400);
            exit();
        }
        if ($request["username"] !== $_SESSION["auth_username"]) {
            echoData(array("error" => "Session Username mismatch"), 400);
            exit();
        }

        $style = $_COOKIE["mcauth_style"];

        unset($_COOKIE["mcauth_id"]);
        unset($_COOKIE["mcauth_request_id"]);
        unset($_COOKIE["mcauth_username"]);
        unset($_COOKIE["mcauth_style"]);
        session_unset();

        $redirectUrl = $request["request_callback"] . "?id=" . $request["_id"] . "&request_id=" . $request["request_id"] . "&code=" . $request["code"];
        if ($style === "simple") {
            echo "You should be redirected automatically. If not, <a href='$redirectUrl'>click here</a>.";
            echo "<script>top.window.location = '$redirectUrl';</script>";
        } else {
            header("Location: " . $redirectUrl);
        }
        exit();
    });

    // Final API request
    $app->post("/status/:id", function ($id) use ($app) {
        $requestId = getParam($app, "request_id");
        $secret = getParam($app, "request_secret");
        $code = getParam($app, "code");

        $request = requests()->find(array(
            "_id" => $id));
        if ($request->count() == 0) {
            echoData(array("error" => "Request not found"), 404);
            exit();
        }
        $request = dbToJson($request);

        if ($request["request_id"] !== $requestId) {
            echoData(array("error" => "Request ID mismatch"), 400);
            exit();
        }
        if ($request["request_secret"] !== $secret) {
            echoData(array("error" => "Request Secret mismatch"), 400);
            exit();
        }
        if ($request["code"] !== $code) {
            echoData(array("error" => "Code mismatch"), 400);
            exit();
        }

        echoData(array(
            "id" => $id,
            "request_id" => $requestId,
            "status" => $request["status"] === "VERIFIED" ? "VERIFIED" : "NOT_VERIFIED",
            "fail_reason" => $request["status"] === "VERIFIED" ? "" : $request["status"]
        ));
    });

});

$app->group("/util", function () use ($app) {

    $app->post("/usernameCheck", function () use ($app) {
        $username = getParam($app, "username");

        $check = checkUsername($app, $username);
        if ($check === false) {
            echoData(array("valid" => false, "username" => $username, "uuid" => ""));
        } else {
            echoData(array("valid" => true, "username" => $username, "uuid" => $check));
        }
    });

});

function checkUsername($app, $username)
{
    $ch = curl_init("https://api.mojang.com/users/profiles/minecraft/" . $username);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $result = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    $json = json_decode($result, true);

    if ($code === 204) {// Username not found
        return false;
    }
    return $json["id"];
}

function getParam($app, $param)
{
    $value = $app->request()->params($param);
    if (!isset($value) || empty($value)) {
        echoData(array("error" => "Missing parameter: " . $param), 400);
        exit();
    }
    return $value;
}


// Run
$app->run();

function echoData($json, $status = 0)
{
    $app = \Slim\Slim::getInstance();

    $app->response()->header("X-Api-Time", time());
    $app->response()->header("Connection", "close");

    $paramPretty = $app->request()->params("pretty");
    $pretty = true;
    if (!is_null($paramPretty)) {
        $pretty = $paramPretty !== "false";
    }

    if ($status !== 0) {
        $app->response->setStatus($status);
        http_response_code($status);
    }

    $app->contentType("application/json; charset=utf-8");
    header("Content-Type: application/json; charset=utf-8");

    $serialized = "{}";
    if ($pretty) {
        $serialized = json_encode($json, JSON_PRETTY_PRINT, JSON_UNESCAPED_UNICODE);
    } else {
        $serialized = json_encode($json, JSON_UNESCAPED_UNICODE);
    }

    $jsonpCallback = $app->request()->params("callback");
    if (!is_null($jsonpCallback)) {
        echo $jsonpCallback . "(" . $serialized . ")";
    } else {
        echo $serialized;
    }
}
