<?php
session_start();
require 'db_connection.php'; // Include your database connection file

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $username = htmlspecialchars($_POST['username']);
    $password = htmlspecialchars($_POST['password']);

    // Prepare and execute query to check credentials
    $stmt = $conn->prepare("SELECT password FROM account_registration WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $stmt->bind_result($hashed_password);
    $stmt->fetch();

    if ($hashed_password && password_verify($password, $hashed_password)) {
        $stmt->close();
        $stmt = $conn->prepare("SELECT * FROM account_registration WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();
        $user = $result->fetch_assoc();

        $_SESSION['user_data'] = $user;
        header("Location: LearnCore_Homepage.html");
        exit;
    } else {
        $_SESSION['error'] = 'Invalid username or password. Please try again.';
        echo "<script>alert('Invalid username or password. Please try again.');</script>";
        header("Location: LearnCore_Login_V2.html");
        exit;
    }
} else {
    header("Location: login.html");
    exit;
}
?>
