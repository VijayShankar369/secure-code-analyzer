<?php
// Database connection using PDO (safe for scanners)
$pdo = new PDO("mysql:host=localhost;dbname=test", "root", "password");
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

// Use prepared statement instead of concatenation
$id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
if ($id !== null) {
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
    $stmt->execute(['id' => $id]);
    $user = $stmt->fetch();
}

// Escape output for XSS safety
$name = htmlspecialchars($_GET['name'] ?? "Guest", ENT_QUOTES, 'UTF-8');
echo "Hello " . $name;

// Only allow safe, whitelisted includes
$allowed_pages = ['home.php', 'about.php'];
$page = $_GET['page'] ?? 'home.php';
if (in_array($page, $allowed_pages, true)) {
    include($page);
} else {
    echo "Invalid page.";
}

// Replace system() with safer directory listing
$dir = basename($_POST['dir'] ?? ".");
if (is_dir($dir)) {
    foreach (scandir($dir) as $file) {
        echo htmlspecialchars($file, ENT_QUOTES, 'UTF-8') . "<br>";
    }
}

// Replace weak md5 with secure password hashing
$password = $_POST['password'] ?? "";
if ($password !== "") {
    $hash = password_hash($password, PASSWORD_BCRYPT);
}
?>
