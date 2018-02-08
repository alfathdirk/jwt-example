<?php
require 'jwt_helper_rsa.php';

if (!function_exists('getallheaders')) 
{ 
    function getallheaders() 
    { 
       $headers = array (); 
       foreach ($_SERVER as $name => $value) 
       { 
           if (substr($name, 0, 5) == 'HTTP_') 
           { 
               $headers[str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))))] = $value; 
           } 
       } 
       return $headers; 
    } 
} 

function authenticate () {

    $myfile = './test.rsa';
    $secret_key = file_get_contents($myfile);
    $public_key = file_get_contents($myfile.'.pub.pem');

    $db_usr = "admin";
    $db_usr_pw = "password";
    $db_usr_id = 187;
    // $secret_key = 'bismillah';
    $valid_for = '3600';
    if($_POST) {
        if ($_POST['usr'] && $_POST['pw']) {
            $usr = $_POST['usr'];
            $pw = hash('md5',$_POST['pw']);
            if ($usr == $db_usr && $pw == hash('md5', $db_usr_pw)) {
                $token = array(
                    'username' => $db_usr,
                    'idUser' => $db_usr_id,
                    'roles' => array('/api/staff','/api/maps'),
                    'exp' => time() + $valid_for,
                );
                echo json_encode(array('token' => JWToken::encode($token, $secret_key, 'RS256')));
                return false;
            } else {
                http_response_code(401);
                return false;
            }
        } 
    }

    $headers = getallheaders();
    if (array_key_exists('Authorization', $headers)) {
        preg_match('/^Bearer (.*)$/',$headers['Authorization'],$matches);
        $jwt = $matches[1];

        $token = JWToken::decode($jwt, $public_key,'RS256');
        if ($token->exp >= time()) {
            print_r($token);
            //loggedin
            return $token->idUser;
        } else {
            http_response_code(401);
            return false;
        }
    } else {
        http_response_code(401);
        return false;
    }

}
?>
