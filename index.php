<?php
require './auth.php';

$userid = authenticate();

if ($userid != false) {
    echo "logged in!";
} else {
    echo "Not Authorized";
}

?>