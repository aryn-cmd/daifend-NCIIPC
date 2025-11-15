<?php
// index.php
// GitHub Copilot
// Scaffolds a sample repository with vulnerable and safe examples for static analysis/testing.
// Run this file once from the project root (CLI or browser) to create the example files.

function write_file($path, $content) {
    $dir = dirname($path);
    if (!is_dir($dir)) {
        mkdir($dir, 0755, true);
    }
    file_put_contents($path, $content);
    echo "Wrote: $path\n";
}

// README
$readme = <<<MD
# Sample Vulnerable Repository (for code-analysis testing)

This repository contains intentionally vulnerable and corresponding safer example PHP files
for use by static analysis tools, linters, and educational testing.

- /vulnerable  - simple examples that contain common vulnerabilities.
- /safe        - safer rewrites showing mitigations.
- README.md    - this file.
- .gitignore   - recommended ignores.

These examples are intentionally simple and should not be used in production.
MD;
write_file('README.md', $readme);

// .gitignore
$gitignore = <<<TXT
/vendor/
/node_modules/
/uploads/
/.env
TXT;
write_file('.gitignore', $gitignore);

// Vulnerable: SQL Injection (uses string interpolation)
$sql_vuln = <<<'PHP'
<?php
// vulnerable/sql_injection.php
// Do NOT use in production. Intentionally vulnerable to SQL injection.

$id = isset($_GET['id']) ? $_GET['id'] : '0';

// Example using PDO but building a query by concatenation (vulnerable)
try {
    $pdo = new PDO('sqlite::memory:'); // in-memory example DB
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // Create a sample table
    $pdo->exec("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)");
    $pdo->exec("INSERT INTO users (name) VALUES ('Alice'), ('Bob')");

    // UNSAFE: direct interpolation of user input
    $query = "SELECT * FROM users WHERE id = $id";
    $stmt = $pdo->query($query);
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

    header('Content-Type: application/json');
    echo json_encode($rows);
} catch (Exception $e) {
    echo "Error: " . $e->getMessage();
}
PHP;
write_file('vulnerable/sql_injection.php', $sql_vuln);

// Safe: SQL with prepared statements
$sql_safe = <<<'PHP'
<?php
// safe/sql_injection_safe.php
// Safer version using prepared statements and parameter binding.

$id = isset($_GET['id']) ? (int)$_GET['id'] : 0;

try {
    $pdo = new PDO('sqlite::memory:');
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    $pdo->exec("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)");
    $pdo->exec("INSERT INTO users (name) VALUES ('Alice'), ('Bob')");

    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
    $stmt->execute([':id' => $id]);
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

    header('Content-Type: application/json');
    echo json_encode($rows);
} catch (Exception $e) {
    echo "Error: " . $e->getMessage();
}
PHP;
write_file('safe/sql_injection_safe.php', $sql_safe);

// Vulnerable: Stored XSS
$xss_vuln = <<<'PHP'
<?php
// vulnerable/xss.php
// Intentionally echoes user input without escaping (stored/reflected XSS example).

$name = isset($_GET['name']) ? $_GET['name'] : 'Guest';
?>
<!doctype html>
<html>
  <head><meta charset="utf-8"><title>Vulnerable XSS</title></head>
  <body>
    <h1>Welcome</h1>
    <p>Hello, <?php echo $name; ?></p>
  </body>
</html>
PHP;
write_file('vulnerable/xss.php', $xss_vuln);

// Safe: Escaped output
$xss_safe = <<<'PHP'
<?php
// safe/xss_safe.php
// Escapes output to prevent XSS.

$name = isset($_GET['name']) ? $_GET['name'] : 'Guest';
?>
<!doctype html>
<html>
  <head><meta charset="utf-8"><title>Safe XSS</title></head>
  <body>
    <h1>Welcome</h1>
    <p>Hello, <?php echo htmlspecialchars($name, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); ?></p>
  </body>
</html>
PHP;
write_file('safe/xss_safe.php', $xss_safe);

// Vulnerable: Insecure file upload
$file_upload_vuln = <<<'PHP'
<?php
// vulnerable/file_upload.php
// Demonstrates an insecure file upload handler (no validation, no filename sanitization).

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $targetDir = __DIR__ . '/uploads';
    if (!is_dir($targetDir)) mkdir($targetDir, 0777, true);

    // UNSAFE: using original filename directly
    $dest = $targetDir . '/' . basename($_FILES['file']['name']);
    if (move_uploaded_file($_FILES['file']['tmp_name'], $dest)) {
        echo "Uploaded to: " . $dest;
    } else {
        echo "Upload failed.";
    }
    exit;
}
?>
<!doctype html>
<html>
  <body>
    <form method="post" enctype="multipart/form-data">
      <input type="file" name="file">
      <button type="submit">Upload</button>
    </form>
  </body>
</html>
PHP;
write_file('vulnerable/file_upload.php', $file_upload_vuln);

// Safe: File upload with validation
$file_upload_safe = <<<'PHP'
<?php
// safe/file_upload_safe.php
// Safer upload: checks size, extension, and sanitizes filename.

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $allowed = ['png','jpg','jpeg','gif','txt'];
    $maxSize = 2 * 1024 * 1024; // 2 MB
    $targetDir = __DIR__ . '/uploads';
    if (!is_dir($targetDir)) mkdir($targetDir, 0755, true);

    $orig = $_FILES['file']['name'];
    $ext = strtolower(pathinfo($orig, PATHINFO_EXTENSION));
    if (!in_array($ext, $allowed)) {
        echo "Invalid file type.";
        exit;
    }
    if ($_FILES['file']['size'] > $maxSize) {
        echo "File too large.";
        exit;
    }
    // sanitize filename
    $safeName = preg_replace('/[^A-Za-z0-9._-]/', '_', basename($orig));
    $dest = $targetDir . '/' . $safeName;
    if (move_uploaded_file($_FILES['file']['tmp_name'], $dest)) {
        echo "Uploaded safely to: " . $dest;
    } else {
        echo "Upload failed.";
    }
    exit;
}
?>
<!doctype html>
<html>
  <body>
    <form method="post" enctype="multipart/form-data">
      <input type="file" name="file">
      <button type="submit">Upload</button>
    </form>
  </body>
</html>
PHP;
write_file('safe/file_upload_safe.php', $file_upload_safe);

// Vulnerable: Command injection
$cmd_vuln = <<<'PHP'
<?php
// vulnerable/command_injection.php
// Executes a shell command including unsanitized user input (dangerous).

$ip = isset($_GET['ip']) ? $_GET['ip'] : '127.0.0.1';

// UNSAFE: directly appended to system command
$cmd = 'ping -c 1 ' . $ip;
$output = shell_exec($cmd);
echo "<pre>" . $output . "</pre>";
PHP;
write_file('vulnerable/command_injection.php', $cmd_vuln);

// Safe: Avoid shell, validate input
$cmd_safe = <<<'PHP'
<?php
// safe/command_safe.php
// Avoids shell execution and validates input.

$ip = isset($_GET['ip']) ? $_GET['ip'] : '127.0.0.1';
if (!filter_var($ip, FILTER_VALIDATE_IP)) {
    echo "Invalid IP.";
    exit;
}

// Instead of shelling out, use PHP functions or libraries.
// Example: Use fsockopen to test connectivity (simple, non-blocking example).
$fp = @fsockopen($ip, 80, $errno, $errstr, 1);
if ($fp) {
    echo "Host reachable on port 80";
    fclose($fp);
} else {
    echo "Host not reachable";
}
PHP;
write_file('safe/command_safe.php', $cmd_safe);

// Vulnerable: Open redirect
$redir_vuln = <<<'PHP'
<?php
// vulnerable/redirect.php
// Performs an open redirect based on user input.

$url = isset($_GET['url']) ? $_GET['url'] : 'https://example.com';
header('Location: ' . $url);
exit;
PHP;
write_file('vulnerable/redirect.php', $redir_vuln);

// Safe: Validate redirect targets
$redir_safe = <<<'PHP'
<?php
// safe/redirect_safe.php
// Only allows redirects to a whitelist of domains.

$allowed = ['example.com', 'example.org'];
$url = isset($_GET['url']) ? $_GET['url'] : 'https://example.com';

$host = parse_url($url, PHP_URL_HOST);
if (in_array($host, $allowed, true)) {
    header('Location: ' . $url);
    exit;
}
echo "Invalid redirect target.";
PHP;
write_file('safe/redirect_safe.php', $redir_safe);

// Simple index listing created files
$index = <<<'PHP'
<?php
// index.php - repository index (auto-generated)
$files = [
    'vulnerable/sql_injection.php',
    'vulnerable/xss.php',
    'vulnerable/file_upload.php',
    'vulnerable/command_injection.php',
    'vulnerable/redirect.php',
    'safe/sql_injection_safe.php',
    'safe/xss_safe.php',
    'safe/file_upload_safe.php',
    'safe/command_safe.php',
    'safe/redirect_safe.php',
];

echo "<!doctype html><meta charset='utf-8'><title>Sample Repo Index</title><h1>Sample Repo</h1><ul>";
foreach ($files as $f) {
    echo "<li><a href=\"/$f\">$f</a></li>";
}
echo "</ul><p>See README.md for details.</p>";
PHP;
write_file('index.php', $index);

echo "\nScaffold complete.\n";