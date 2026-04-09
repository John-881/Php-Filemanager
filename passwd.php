<?php
/**
 * Bcrypt 密码哈希生成工具
 * 使用方法：将此文件保存为 index.php 并放入支持 PHP 的服务器即可。
 */

$message = '';
$password = '';
$cost = 10; // 默认成本因子
$hash = '';

// 处理表单提交
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $password = $_POST['password'] ?? '';
    $cost = (int)($_POST['cost'] ?? 10);
    $action = $_POST['action'] ?? '';

    if (!empty($password)) {
        // 确保成本在有效范围内 (4-31)
        if ($cost < 4) $cost = 4;
        if ($cost > 31) $cost = 31;

        if ($action === 'generate') {
            // 使用 PASSWORD_BCRYPT 算法生成哈希
            // PASSWORD_DEFAULT 目前也是 Bcrypt，但显式指定 BCRYPT 更符合你的需求
            $hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => $cost]);
            $message = '<div class="alert success">哈希生成成功！</div>';
        } elseif ($action === 'verify') {
            $checkHash = $_POST['hash_to_check'] ?? '';
            if (!empty($checkHash)) {
                if (password_verify($password, $checkHash)) {
                    $message = '<div class="alert success">验证通过：密码匹配！</div>';
                } else {
                    $message = '<div class="alert error">验证失败：密码不匹配。</div>';
                }
            }
        }
    } else {
        $message = '<div class="alert error">请输入密码。</div>';
    }
}
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bcrypt 在线生成工具</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; background-color: #f4f4f9; display: flex; justify-content: center; padding-top: 50px; color: #333; }
        .container { background: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); width: 100%; max-width: 600px; }
        h1 { text-align: center; color: #444; margin-bottom: 30px; font-size: 24px; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 8px; font-weight: bold; }
        input[type="text"], input[type="password"], input[type="number"] { width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; font-size: 14px; transition: border 0.3s; }
        input:focus { border-color: #007BFF; outline: none; }
        button { width: 100%; padding: 12px; background-color: #007BFF; color: white; border: none; border-radius: 4px; font-size: 16px; cursor: pointer; transition: background 0.3s; }
        button:hover { background-color: #0056b3; }
        .result-box { background: #f8f9fa; padding: 15px; border-radius: 4px; border: 1px solid #e9ecef; word-break: break-all; font-family: monospace; color: #333; margin-top: 10px; }
        .alert { padding: 15px; border-radius: 4px; margin-bottom: 20px; text-align: center; }
        .success { background-color: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .error { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .divider { margin: 30px 0; border-top: 1px solid #eee; }
        .secondary-btn { background-color: #6c757d; margin-top: 10px; }
        .secondary-btn:hover { background-color: #545b62; }
    </style>
</head>
<body>

<div class="container">
    <h1>🔐 Bcrypt 哈希生成器</h1>

    <?php echo $message; ?>

    <!-- 生成表单 -->
    <form method="POST">
        <div class="form-group">
            <label for="password">输入密码 / 字符串:</label>
            <input type="text" name="password" id="password" value="<?php echo htmlspecialchars($password); ?>" placeholder="在此输入..." required>
        </div>

        <div class="form-group">
            <label for="cost">成本因子 (Cost):</label>
            <input type="number" name="cost" id="cost" value="<?php echo $cost; ?>" min="4" max="31">
            <small style="color: #666; display: block; margin-top: 5px;">推荐值：10。值越大越安全，但生成速度越慢。</small>
        </div>

        <button type="submit" name="action" value="generate">生成哈希</button>
    </form>

    <?php if ($hash): ?>
    <div class="result-box">
        <strong>生成的哈希:</strong><br>
        <?php echo htmlspecialchars($hash); ?>
    </div>
    <?php endif; ?>

    <div class="divider"></div>

    <!-- 验证表单 -->
    <h3 style="text-align: center; margin-bottom: 20px;">验证哈希</h3>
    <form method="POST">
        <div class="form-group">
            <label for="password">输入密码:</label>
            <input type="text" name="password" value="<?php echo htmlspecialchars($password); ?>" required>
        </div>
        <div class="form-group">
            <label for="hash_to_check">输入哈希值:</label>
            <input type="text" name="hash_to_check" placeholder="$2y$..." required>
        </div>
        <button type="submit" name="action" value="verify" class="secondary-btn">验证匹配</button>
    </form>
</div>

</body>
</html>