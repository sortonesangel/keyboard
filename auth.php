<?php
// Enable error reporting for debugging
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Database configuration
$servername = "localhost";
$username = "root"; // Replace with your database username
$password = "";     // Replace with your database password
$dbname = "user_db";

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Handle form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['register'])) {
        // Registration logic
        $firstName = $_POST['first_name'];
        $lastName = $_POST['last_name'];
        $middleName = $_POST['middle_name'];
        $username = $_POST['username'];
        $email = $_POST['email'];
        $password = trim($_POST['password']);
        $confirmPassword = isset($_POST['confirm_password']) ? trim($_POST['confirm_password']) : ''; // Handle unset value
        $birthdate = $_POST['birthdate'];
        $address = $_POST['address'];
        $contactNumber = $_POST['contact_number'];

        // Check if passwords match
        if ($password !== $confirmPassword) {
            echo "Passwords do not match!";
            exit;
        }

        // Hash the password
        $hashedPassword = password_hash($password, PASSWORD_BCRYPT);

        // Prepare and execute the SQL statement
        $stmt = $conn->prepare("INSERT INTO users (first_name, last_name, middle_name, username, email, password, birthdate, address, contact_number) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
        $stmt->bind_param("sssssssss", $firstName, $lastName, $middleName, $username, $email, $hashedPassword, $birthdate, $address, $contactNumber);

        if ($stmt->execute()) {
            echo "Registration successful!";
        } else {
            echo "Error: " . $stmt->error;
        }

        $stmt->close();
    } elseif (isset($_POST['login'])) {
        // Login logic
        $usernameOrEmail = $_POST['username_or_email'];
        $password = trim($_POST['password']);

        // Prepare and execute the SQL statement
        $stmt = $conn->prepare("SELECT password FROM users WHERE username = ? OR email = ?");
        $stmt->bind_param("ss", $usernameOrEmail, $usernameOrEmail);
        $stmt->execute();
        $stmt->bind_result($hashedPassword);
        $stmt->fetch();

        if (password_verify($password, $hashedPassword)) {
            echo "Login successful!";
        } else {
            echo "Invalid credentials!";
        }

        $stmt->close();
    }
}

$conn->close();
?>
