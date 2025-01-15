<?php
session_start();
if (isset($_SESSION["user"])) {
    header("Location: index.php");
    exit();
}
?>


<?php 

if (isset($_POST["submit"])) {
    $fullName = $_POST["fullname"];
    $email = $_POST["email"];
    $password = $_POST["password"];
    $confirmPassword = $_POST["confirmPassword"];
    $passwordHash = password_hash($password, PASSWORD_DEFAULT);
    $errors = array();

    if (empty($fullName) || empty($email) || empty($password) || empty($confirmPassword)) {
        array_push($errors, "All fields are required");
    }
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        array_push($errors, "Email is not valid");
    }
    if (strlen($password) < 8) {
        array_push($errors, "Password must be at least 8 characters");
    }
    if ($password !== $confirmPassword) {
        array_push($errors, "Passwords do not match");
    }

    require_once "database.php";

    if ($conn === false) {
        die("<div class='alert alert-danger'>Database connection failed</div>");
    }

    $sql = "SELECT * FROM userrl WHERE email = ?";
    $stmt = mysqli_stmt_init($conn);
    if (mysqli_stmt_prepare($stmt, $sql)) {
        mysqli_stmt_bind_param($stmt, "s", $email);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);
        $rowCount = mysqli_num_rows($result);
        if ($rowCount > 0) {
            array_push($errors, "Email already exists!");
        }
    } else {
        die("<div class='alert alert-danger'>Something went wrong with the SQL query</div>");
    }

    if (count($errors) > 0) {
        foreach ($errors as $error) {
            echo "<div class='alert alert-danger'>$error</div>";
        }
    } else {
        $sql = "INSERT INTO userrl (full_name, email, password) VALUES (?, ?, ?)";
        if (mysqli_stmt_prepare($stmt, $sql)) {
            // Bind parameters and execute statement
            mysqli_stmt_bind_param($stmt, "sss", $fullName, $email, $passwordHash);
            mysqli_stmt_execute($stmt);
            echo "<div class='alert alert-success'>User registered successfully</div>";
        } else {
            die("<div class='alert alert-danger'>Something went wrong with the SQL query</div>");
        }
    }
}
?>