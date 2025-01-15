<?php
session_start();
if (isset($_SESSION["user"])) {
    header("Location: index.php");
    exit();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register</title>
    <link rel="stylesheet" href="Lcss/Lstyle.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.7.2/css/all.min.css"> 
    <!-- <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous"> -->
</head>
<body class="bg-dark">
    <main>
        <div class="container">
            <div class="login-box">
                <h1>Register</h1>

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
        die("<div style='color:red; margin:10px 0; font-size: 1.1em; text-align:center;>Database connection failed</div>");
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
        die("<div style='color:red; margin:10px 0; font-size: 1.1em; text-align:center;>Something went wrong with the SQL query</div>");
    }

    if (count($errors) > 0) {
        foreach ($errors as $error) {
            echo "<div style='color:red; margin:10px 0; font-size: 1.1em; text-align:center;' >$error</div>";
        }
    } else {
        $sql = "INSERT INTO userrl (full_name, email, password) VALUES (?, ?, ?)";
        if (mysqli_stmt_prepare($stmt, $sql)) {
            // Bind parameters and execute statement
            mysqli_stmt_bind_param($stmt, "sss", $fullName, $email, $passwordHash);
            mysqli_stmt_execute($stmt);
            echo "<div style='color: black; margin:10px 0; font-size: 1.3em; text-align:center;'>User registered successfully</div>";
        } else {
            die("<div style='color:red; margin:10px 0; font-size: 1.1em; text-align:center;>Something went wrong with the SQL query</div>");
        }
    }
}
?>
                <form action="Signup.php" method="post">
                    <div class="textbox">
                        <input type="text" placeholder="Username" name='fullname' required>
                    </div>
                    <div class="textbox">
                        <input type="text" placeholder="Email" name="email" required>
                    </div>
                    <div class="textbox">
                        <input type="password" placeholder="Password" name="password" id="password" required>
                        <i class="fa-regular fa-eye-slash" id="eyeicon"></i>
                    </div>
                    <div class="textbox">
                        <input type="password" placeholder="Confirm Password" name="confirmPassword" id="password" required>
                        <i class="fa-regular fa-eye-slash" id="eyeicon"></i>
                    </div>
                    <input type="submit" value="Register" name="submit" class="btn btn-primary btn-lg px-2">            
                </form>
               
                <a href="Login.php" class=" text-start" style="margin-left:20%;">Already I Have an Account? </a>

            </div>
        </div>
    </main>
    <script src="JS/Lscript.js"></script>
</body>
</html>