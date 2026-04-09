<?php
/**
 * PHP File Manager - Security Enhanced Version (Final)
 * Original: https://github.com/alexantr/filemanager
 * Enhanced for PHP 8.3 with comprehensive security improvements
 * Version: 2.0-secure-final
 */

// --- 安全配置 ---
$use_auth = true;

// 用户凭证 - 请立即修改默认密码！
// 密码哈希生成: password_hash('your_password', PASSWORD_DEFAULT)
$auth_users = array(
    'admin' => '', // 请使用 password_hash() 生成新密码
);

$readonly_users = array();
$global_readonly = false;
$directories_users = array();

$use_highlightjs = true;
$highlightjs_style = 'vs';
$default_timezone = 'UTC';
$root_path = $_SERVER['DOCUMENT_ROOT'];
$root_url = '';
$http_host = $_SERVER['HTTP_HOST'] ?? 'localhost';
$iconv_input_encoding = 'UTF-8';
$datetime_format = 'Y-m-d H:i:s';
$allowed_file_extensions = '';
$allowed_upload_extensions = 'jpg,jpeg,png,gif,pdf,doc,docx,xls,xlsx,txt,zip';
$show_hidden_files = true;
$hide_Cols = false;
$exclude_items = array();
$online_viewer = 'google';
$max_upload_size_bytes = 104857600;
$ip_ruleset = 'OFF';
$ip_whitelist = array('127.0.0.1', '::1');
$ip_blacklist = array();
$path_display_mode = 'full';
$csrf_protection = true;

// 会话配置
define('FM_SESSION_ID', 'filemanager_secure');
define('VERSION', '2.0-secure-final');

// 安全常量
define('FM_MIN_PASSWORD_LENGTH', 8);
define('FM_MAX_LOGIN_ATTEMPTS', 5);
define('FM_LOGIN_TIMEOUT', 900); // 15分钟锁定

// --- 以下一般不需要修改 ---

$is_https = isset($_SERVER['HTTPS']) && (strtolower($_SERVER['HTTPS']) == 'on' || $_SERVER['HTTPS'] == 1)
    || isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] == 'https';

$config_file = __DIR__ . '/filemanager_config.php';
if (is_readable($config_file)) {
    include $config_file;
}

// 初始化会话
if (!defined('FM_EMBED')) {
    @set_time_limit(600);
    date_default_timezone_set($default_timezone);
    ini_set('default_charset', 'UTF-8');
    
    if (version_compare(PHP_VERSION, '5.6.0', '<') && function_exists('mb_internal_encoding')) {
        mb_internal_encoding('UTF-8');
    }
    if (function_exists('mb_regex_encoding')) {
        mb_regex_encoding('UTF-8');
    }

    session_cache_limiter('nocache');
    session_name(FM_SESSION_ID);
    
    // 安全会话配置
    ini_set('session.cookie_httponly', '1');
    ini_set('session.cookie_samesite', 'Strict');
    ini_set('session.use_strict_mode', '1');
    if ($is_https) {
        ini_set('session.cookie_secure', '1');
    }
    
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
}

// CSRF Token 管理
if ($csrf_protection) {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    // Token 过期检查 (1小时)
    if (!empty($_SESSION['csrf_token_time']) && time() - $_SESSION['csrf_token_time'] > 3600) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    $_SESSION['csrf_token_time'] = time();
}

function verify_csrf_token($token) {
    global $csrf_protection;
    if (!$csrf_protection) return true;
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

function get_csrf_token() {
    global $csrf_protection;
    return $csrf_protection ? ($_SESSION['csrf_token'] ?? '') : '';
}

if (empty($auth_users)) {
    $use_auth = false;
}

// 清理根路径
$root_path = rtrim($root_path, '\\/');
$root_path = str_replace('\\', '/', $root_path);
$root_path = realpath($root_path) ?: $root_path;

if (!@is_dir($root_path)) {
    http_response_code(500);
    die(sprintf('<h1>Root path "%s" not found!</h1>', fm_enc($root_path)));
}

$root_url = fm_clean_path($root_url);

defined('FM_ROOT_PATH') || define('FM_ROOT_PATH', $root_path);
defined('FM_ROOT_URL') || define('FM_ROOT_URL', ($is_https ? 'https' : 'http') . '://' . $http_host . (!empty($root_url) ? '/' . $root_url : ''));
defined('FM_SELF_URL') || define('FM_SELF_URL', ($is_https ? 'https' : 'http') . '://' . $http_host . $_SERVER['PHP_SELF']);

// 登出
if (isset($_GET['logout'])) {
    $_SESSION = array();
    if (isset($_COOKIE[session_name()])) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'], $params['secure'], $params['httponly']);
    }
    session_destroy();
    fm_redirect(FM_SELF_URL);
}

// 显示图片
if (isset($_GET['img'])) {
    fm_show_image($_GET['img']);
}

// IP 验证
if ($ip_ruleset != 'OFF') {
    $clientIp = getClientIP();
    $whitelisted = in_array($clientIp, $ip_whitelist);
    $blacklisted = in_array($clientIp, $ip_blacklist);
    $proceed = false;

    if ($ip_ruleset == 'AND' && $whitelisted && !$blacklisted) {
        $proceed = true;
    } elseif ($ip_ruleset == 'OR' && ($whitelisted || !$blacklisted)) {
        $proceed = true;
    }

    if (!$proceed) {
        http_response_code(403);
        die('Access denied. IP restriction applicable.');
    }
}

// 登录失败限制
if (!isset($_SESSION['login_attempts'])) {
    $_SESSION['login_attempts'] = 0;
    $_SESSION['login_lock_time'] = 0;
}

// 认证
if ($use_auth) {
    if (isset($_SESSION['logged'], $auth_users[$_SESSION['logged']])) {
        // 已登录 - 验证会话完整性
        if (!isset($_SESSION['user_agent'])) {
            $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'] ?? '';
            $_SESSION['ip_address'] = getClientIP();
        } elseif ($_SESSION['user_agent'] !== ($_SERVER['HTTP_USER_AGENT'] ?? '') || 
                  $_SESSION['ip_address'] !== getClientIP()) {
            // 会话劫持检测
            unset($_SESSION['logged']);
            fm_set_msg('Session security check failed. Please login again.', 'error');
            fm_redirect(FM_SELF_URL);
        }
        
        if (isset($directories_users[$_SESSION['logged']])) {
            $root_path = $directories_users[$_SESSION['logged']];
            if (!@is_dir($root_path)) {
                $root_path = FM_ROOT_PATH;
            }
        }
        
        $is_readonly = $global_readonly || in_array($_SESSION['logged'], $readonly_users);
    } elseif (isset($_POST['fm_usr'], $_POST['fm_pwd'])) {
        // 登录处理
        sleep(1);
        
        // 检查锁定状态
        if ($_SESSION['login_lock_time'] > time()) {
            $remaining = $_SESSION['login_lock_time'] - time();
            fm_set_msg("Too many failed attempts. Please wait {$remaining} seconds.", 'error');
            fm_redirect(FM_SELF_URL);
        }
        
        if ($csrf_protection && !verify_csrf_token($_POST['csrf_token'] ?? '')) {
            fm_set_msg('Invalid security token', 'error');
            fm_redirect(FM_SELF_URL);
        }
        
        $username = trim($_POST['fm_usr']);
        $password = $_POST['fm_pwd'];
        
        // 输入长度限制
        if (strlen($username) > 64 || strlen($password) > 128) {
            fm_set_msg('Invalid input length', 'error');
            fm_redirect(FM_SELF_URL);
        }
        
        if (isset($auth_users[$username])) {
            $stored_hash = $auth_users[$username];
            
            if (password_get_info($stored_hash)['algo'] > 0) {
                $valid = password_verify($password, $stored_hash);
            } else {
                $valid = ($password === $stored_hash);
            }
            
            if ($valid) {
                // 登录成功
                $_SESSION['login_attempts'] = 0;
                $_SESSION['login_lock_time'] = 0;
                session_regenerate_id(true);
                $_SESSION['logged'] = $username;
                $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'] ?? '';
                $_SESSION['ip_address'] = getClientIP();
                $_SESSION['login_time'] = time();
                fm_set_msg('You are logged in');
                fm_redirect(FM_SELF_URL . '?p=');
            } else {
                // 登录失败
                $_SESSION['login_attempts']++;
                if ($_SESSION['login_attempts'] >= FM_MAX_LOGIN_ATTEMPTS) {
                    $_SESSION['login_lock_time'] = time() + FM_LOGIN_TIMEOUT;
                    fm_set_msg('Too many failed attempts. Account locked for 15 minutes.', 'error');
                } else {
                    $remaining = FM_MAX_LOGIN_ATTEMPTS - $_SESSION['login_attempts'];
                    fm_set_msg("Wrong password. {$remaining} attempts remaining.", 'error');
                }
                unset($_SESSION['logged']);
                fm_redirect(FM_SELF_URL);
            }
        } else {
            $_SESSION['login_attempts']++;
            fm_set_msg('Wrong username or password', 'error');
            unset($_SESSION['logged']);
            fm_redirect(FM_SELF_URL);
        }
    } else {
        // 显示登录表单
        unset($_SESSION['logged']);
        fm_show_header();
        fm_show_message();
        $remaining_attempts = FM_MAX_LOGIN_ATTEMPTS - ($_SESSION['login_attempts'] ?? 0);
        $is_locked = ($_SESSION['login_lock_time'] ?? 0) > time();
        ?>
        <div class="path">
            <div class="login-form">
                <h2 style="margin-bottom:20px">PHP File Manager</h2>
                <?php if ($is_locked): ?>
                    <p style="color:#dc2626">Account temporarily locked. Please wait <?php echo $_SESSION['login_lock_time'] - time(); ?> seconds.</p>
                <?php else: ?>
                    <form action="" method="post" style="margin:10px;text-align:center">
                        <input type="text" name="fm_usr" value="" placeholder="Username" required autocomplete="username" maxlength="64" style="padding:8px;margin:5px;width:200px"><br>
                        <input type="password" name="fm_pwd" value="" placeholder="Password" required autocomplete="current-password" maxlength="128" style="padding:8px;margin:5px;width:200px"><br>
                        <input type="hidden" name="csrf_token" value="<?php echo fm_enc(get_csrf_token()); ?>">
                        <input type="submit" value="Login" style="padding:8px 30px;margin:10px;cursor:pointer">
                    </form>
                    <?php if ($_SESSION['login_attempts'] > 0): ?>
                        <p style="color:#dc2626">Remaining attempts: <?php echo $remaining_attempts; ?></p>
                    <?php endif; ?>
                <?php endif; ?>
            </div>
        </div>
        <?php
        fm_show_footer();
        exit;
    }
} else {
    $is_readonly = $global_readonly;
}

define('FM_IS_WIN', DIRECTORY_SEPARATOR == '\\');
define('FM_READONLY', $is_readonly ?? false);

// 始终使用 ?p=
if (!isset($_GET['p']) && empty($_FILES)) {
    fm_redirect(FM_SELF_URL . '?p=');
}

// 获取路径
$p = $_GET['p'] ?? ($_POST['p'] ?? '');

// 清理并验证路径
$p = fm_clean_path($p);
$full_path = FM_ROOT_PATH;
if ($p != '') {
    $full_path .= '/' . $p;
}

// 验证路径在根目录内
$real_full_path = realpath($full_path);
$real_root_path = realpath(FM_ROOT_PATH);

if ($real_full_path === false || $real_root_path === false || 
    strpos($real_full_path, $real_root_path) !== 0) {
    fm_set_msg('Invalid path', 'error');
    fm_redirect(FM_SELF_URL . '?p=');
}

define('FM_PATH', $p);
define('FM_USE_AUTH', $use_auth);

defined('FM_ICONV_INPUT_ENC') || define('FM_ICONV_INPUT_ENC', $iconv_input_encoding);
defined('FM_USE_HIGHLIGHTJS') || define('FM_USE_HIGHLIGHTJS', $use_highlightjs);
defined('FM_HIGHLIGHTJS_STYLE') || define('FM_HIGHLIGHTJS_STYLE', $highlightjs_style);
defined('FM_DATETIME_FORMAT') || define('FM_DATETIME_FORMAT', $datetime_format);
defined('FM_SHOW_HIDDEN') || define('FM_SHOW_HIDDEN', $show_hidden_files);
defined('FM_HIDE_COLS') || define('FM_HIDE_COLS', $hide_Cols);
defined('FM_EXCLUDE_ITEMS') || define('FM_EXCLUDE_ITEMS', $exclude_items);
defined('FM_UPLOAD_EXT') || define('FM_UPLOAD_EXT', $allowed_upload_extensions);
defined('FM_FILE_EXT') || define('FM_FILE_EXT', $allowed_file_extensions);

/*************************** ACTIONS ***************************/

function check_write_permission() {
    if (FM_READONLY) {
        fm_set_msg('Write operations are disabled', 'error');
        fm_redirect(FM_SELF_URL . '?p=' . urlencode(FM_PATH));
    }
}

function is_allowed_extension($filename, $type = 'file') {
    $allowed = ($type == 'upload') ? FM_UPLOAD_EXT : FM_FILE_EXT;
    if (empty($allowed)) return true;
    
    $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    if (empty($ext)) return true;
    
    $allowed_arr = array_map('trim', explode(',', $allowed));
    return in_array($ext, $allowed_arr);
}

function is_excluded($name, $path) {
    $exclude_items = FM_EXCLUDE_ITEMS;
    if (empty($exclude_items)) return false;
    
    $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
    return in_array($name, $exclude_items) || 
           in_array("*.$ext", $exclude_items) || 
           in_array($path, $exclude_items);
}

// 删除文件/文件夹
if (isset($_GET['del'])) {
    check_write_permission();
    
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        fm_set_msg('Invalid security token', 'error');
        fm_redirect(FM_SELF_URL . '?p=' . urlencode(FM_PATH));
    }
    
    $del = fm_clean_path($_GET['del']);
    $del = str_replace('/', '', $del);
    
    if ($del != '' && $del != '..' && $del != '.') {
        $path = FM_ROOT_PATH;
        if (FM_PATH != '') {
            $path .= '/' . FM_PATH;
        }
        
        $target_path = $path . '/' . $del;
        $real_target = realpath($target_path);
        $real_base = realpath(FM_ROOT_PATH);
        
        if ($real_target === false || strpos($real_target, $real_base) !== 0) {
            fm_set_msg('Invalid file path', 'error');
        } else {
            $is_dir = is_dir($real_target);
            if (fm_rdelete($real_target)) {
                $msg = $is_dir ? 'Folder <b>%s</b> deleted' : 'File <b>%s</b> deleted';
                fm_set_msg(sprintf($msg, fm_enc($del)));
            } else {
                $msg = $is_dir ? 'Folder <b>%s</b> not deleted' : 'File <b>%s</b> not deleted';
                fm_set_msg(sprintf($msg, fm_enc($del)), 'error');
            }
        }
    } else {
        fm_set_msg('Wrong file or folder name', 'error');
    }
    fm_redirect(FM_SELF_URL . '?p=' . urlencode(FM_PATH));
}

// 创建文件夹
if (isset($_GET['new'])) {
    check_write_permission();
    
    $token = $_POST['csrf_token'] ?? $_GET['csrf_token'] ?? '';
    if (!verify_csrf_token($token)) {
        fm_set_msg('Invalid security token', 'error');
        fm_redirect(FM_SELF_URL . '?p=' . urlencode(FM_PATH));
    }
    
    $new = strip_tags($_GET['new']);
    $new = fm_clean_path($new);
    $new = str_replace('/', '', $new);
    
    // 文件夹名长度限制
    if (strlen($new) > 255) {
        fm_set_msg('Folder name too long', 'error');
        fm_redirect(FM_SELF_URL . '?p=' . urlencode(FM_PATH));
    }
    
    if ($new != '' && $new != '..' && $new != '.') {
        $path = FM_ROOT_PATH;
        if (FM_PATH != '') {
            $path .= '/' . FM_PATH;
        }
        
        if (fm_mkdir($path . '/' . $new, false) === true) {
            fm_set_msg(sprintf('Folder <b>%s</b> created', fm_enc($new)));
        } elseif (fm_mkdir($path . '/' . $new, false) === $path . '/' . $new) {
            fm_set_msg(sprintf('Folder <b>%s</b> already exists', fm_enc($new)), 'alert');
        } else {
            fm_set_msg(sprintf('Folder <b>%s</b> not created', fm_enc($new)), 'error');
        }
    } else {
        fm_set_msg('Wrong folder name', 'error');
    }
    fm_redirect(FM_SELF_URL . '?p=' . urlencode(FM_PATH));
}

// 创建文件
if (isset($_GET['newfile'])) {
    check_write_permission();
    
    $token = $_POST['csrf_token'] ?? $_GET['csrf_token'] ?? '';
    if (!verify_csrf_token($token)) {
        fm_set_msg('Invalid security token', 'error');
        fm_redirect(FM_SELF_URL . '?p=' . urlencode(FM_PATH));
    }
    
    $new = strip_tags($_GET['newfile']);
    $new = fm_clean_path($new);
    $new = str_replace('/', '', $new);
    
    if (strlen($new) > 255) {
        fm_set_msg('File name too long', 'error');
        fm_redirect(FM_SELF_URL . '?p=' . urlencode(FM_PATH));
    }
    
    if ($new != '' && $new != '..' && $new != '.') {
        if (!is_allowed_extension($new, 'file')) {
            fm_set_msg('File extension not allowed', 'error');
        } else {
            $path = FM_ROOT_PATH;
            if (FM_PATH != '') {
                $path .= '/' . FM_PATH;
            }
            
            $file_path = $path . '/' . $new;
            if (!file_exists($file_path)) {
                if (file_put_contents($file_path, '') !== false) {
                    chmod($file_path, 0644);
                    fm_set_msg(sprintf('File <b>%s</b> created', fm_enc($new)));
                } else {
                    fm_set_msg(sprintf('File <b>%s</b> not created', fm_enc($new)), 'error');
                }
            } else {
                fm_set_msg(sprintf('File <b>%s</b> already exists', fm_enc($new)), 'alert');
            }
        }
    } else {
        fm_set_msg('Wrong file name', 'error');
    }
    fm_redirect(FM_SELF_URL . '?p=' . urlencode(FM_PATH));
}

// 复制文件夹/文件
if (isset($_GET['copy'], $_GET['finish'])) {
    check_write_permission();
    
    $token = $_POST['csrf_token'] ?? $_GET['csrf_token'] ?? '';
    if (!verify_csrf_token($token)) {
        fm_set_msg('Invalid security token', 'error');
        fm_redirect(FM_SELF_URL . '?p=' . urlencode(FM_PATH));
    }
    
    $copy = fm_clean_path($_GET['copy']);
    
    if ($copy == '') {
        fm_set_msg('Source path not defined', 'error');
        fm_redirect(FM_SELF_URL . '?p=' . urlencode(FM_PATH));
    }
    
    $from = FM_ROOT_PATH . '/' . $copy;
    $dest = FM_ROOT_PATH;
    if (FM_PATH != '') {
        $dest .= '/' . FM_PATH;
    }
    $dest .= '/' . basename($from);
    $move = isset($_GET['move']);
    
    $real_from = realpath($from);
    $real_dest_dir = realpath(dirname($dest));
    $real_base = realpath(FM_ROOT_PATH);
    
    if ($real_from === false || strpos($real_from, $real_base) !== 0) {
        fm_set_msg('Invalid source path', 'error');
    } elseif ($real_dest_dir === false || strpos($real_dest_dir, $real_base) !== 0) {
        fm_set_msg('Invalid destination path', 'error');
    } elseif ($from != $dest) {
        $msg_from = trim(FM_PATH . '/' . basename($from), '/');
        if ($move) {
            $rename = fm_rename($from, $dest);
            if ($rename) {
                fm_set_msg(sprintf('Moved from <b>%s</b> to <b>%s</b>', fm_enc($copy), fm_enc($msg_from)));
            } elseif ($rename === null) {
                fm_set_msg('File or folder with this path already exists', 'alert');
            } else {
                fm_set_msg(sprintf('Error while moving from <b>%s</b> to <b>%s</b>', fm_enc($copy), fm_enc($msg_from)), 'error');
            }
        } else {
            if (fm_rcopy($from, $dest)) {
                fm_set_msg(sprintf('Copied from <b>%s</b> to <b>%s</b>', fm_enc($copy), fm_enc($msg_from)));
            } else {
                fm_set_msg(sprintf('Error while copying from <b>%s</b> to <b>%s</b>', fm_enc($copy), fm_enc($msg_from)), 'error');
            }
        }
    } else {
        fm_set_msg('Paths must be not equal', 'alert');
    }
    fm_redirect(FM_SELF_URL . '?p=' . urlencode(FM_PATH));
}

// 批量复制
if (isset($_POST['file'], $_POST['copy_to'], $_POST['finish'])) {
    check_write_permission();
    
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        fm_set_msg('Invalid security token', 'error');
        fm_redirect(FM_SELF_URL . '?p=' . urlencode(FM_PATH));
    }
    
    $path = FM_ROOT_PATH;
    if (FM_PATH != '') {
        $path .= '/' . FM_PATH;
    }
    
    $copy_to_path = FM_ROOT_PATH;
    $copy_to = fm_clean_path($_POST['copy_to']);
    if ($copy_to != '') {
        $copy_to_path .= '/' . $copy_to;
    }
    
    if ($path == $copy_to_path) {
        fm_set_msg('Paths must be not equal', 'alert');
        fm_redirect(FM_SELF_URL . '?p=' . urlencode(FM_PATH));
    }
    
    if (!is_dir($copy_to_path)) {
        if (!fm_mkdir($copy_to_path, true)) {
            fm_set_msg('Unable to create destination folder', 'error');
            fm_redirect(FM_SELF_URL . '?p=' . urlencode(FM_PATH));
        }
    }
    
    $move = isset($_POST['move']);
    $errors = 0;
    $files = $_POST['file'];
    
    if (is_array($files) && count($files)) {
        foreach ($files as $f) {
            if ($f != '') {
                $f = fm_clean_path($f);
                $from = $path . '/' . $f;
                $dest = $copy_to_path . '/' . $f;
                
                $real_from = realpath($from);
                $real_dest_dir = realpath(dirname($dest));
                $real_base = realpath(FM_ROOT_PATH);
                
                if ($real_from === false || strpos($real_from, $real_base) !== 0) {
                    $errors++;
                    continue;
                }
                
                if ($move) {
                    $rename = fm_rename($from, $dest);
                    if ($rename === false) $errors++;
                } else {
                    if (!fm_rcopy($from, $dest)) $errors++;
                }
            }
        }
        
        if ($errors == 0) {
            $msg = $move ? 'Selected files and folders moved' : 'Selected files and folders copied';
            fm_set_msg($msg);
        } else {
            $msg = $move ? 'Error while moving items' : 'Error while copying items';
            fm_set_msg($msg, 'error');
        }
    } else {
        fm_set_msg('Nothing selected', 'alert');
    }
    fm_redirect(FM_SELF_URL . '?p=' . urlencode(FM_PATH));
}

// 重命名
if (isset($_GET['ren'], $_GET['to'])) {
    check_write_permission();
    
    $token = $_POST['csrf_token'] ?? $_GET['csrf_token'] ?? '';
    if (!verify_csrf_token($token)) {
        fm_set_msg('Invalid security token', 'error');
        fm_redirect(FM_SELF_URL . '?p=' . urlencode(FM_PATH));
    }
    
    $old = fm_clean_path($_GET['ren']);
    $old = str_replace('/', '', $old);
    $new = fm_clean_path($_GET['to']);
    $new = str_replace('/', '', $new);
    
    if (strlen($new) > 255) {
        fm_set_msg('New name too long', 'error');
        fm_redirect(FM_SELF_URL . '?p=' . urlencode(FM_PATH));
    }
    
    $path = FM_ROOT_PATH;
    if (FM_PATH != '') {
        $path .= '/' . FM_PATH;
    }
    
    $old_path = $path . '/' . $old;
    if (is_file($old_path) && !is_allowed_extension($new, 'file')) {
        fm_set_msg('File extension not allowed', 'error');
    } elseif ($old != '' && $new != '') {
        if (fm_rename($old_path, $path . '/' . $new)) {
            fm_set_msg(sprintf('Renamed from <b>%s</b> to <b>%s</b>', fm_enc($old), fm_enc($new)));
        } else {
            fm_set_msg(sprintf('Error while renaming from <b>%s</b> to <b>%s</b>', fm_enc($old), fm_enc($new)), 'error');
        }
    } else {
        fm_set_msg('Names not set', 'error');
    }
    fm_redirect(FM_SELF_URL . '?p=' . urlencode(FM_PATH));
}

// 下载
if (isset($_GET['dl'])) {
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        fm_set_msg('Invalid security token', 'error');
        fm_redirect(FM_SELF_URL . '?p=' . urlencode(FM_PATH));
    }
    
    $dl = fm_clean_path($_GET['dl']);
    $dl = str_replace('/', '', $dl);
    $path = FM_ROOT_PATH;
    if (FM_PATH != '') {
        $path .= '/' . FM_PATH;
    }
    
    $file_path = $path . '/' . $dl;
    $real_file = realpath($file_path);
    $real_base = realpath(FM_ROOT_PATH);
    
    if ($dl != '' && $real_file !== false && strpos($real_file, $real_base) === 0 && is_file($real_file)) {
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_write_close();
        }
        
        $filename = basename($real_file);
        $mime_type = fm_get_mime_type($real_file);
        $filesize = filesize($real_file);
        
        // 防止大文件导致内存问题
        if ($filesize > 104857600) { // 100MB
            ini_set('memory_limit', '256M');
        }
        
        header('Content-Description: File Transfer');
        header('Content-Type: ' . $mime_type);
        header('Content-Disposition: attachment; filename="' . addslashes($filename) . '"');
        header('Content-Transfer-Encoding: binary');
        header('Expires: 0');
        header('Cache-Control: must-revalidate, post-check=0, pre-check=0');
        header('Pragma: public');
        header('Content-Length: ' . $filesize);
        
        // 使用 readfile 分块输出
        $handle = fopen($real_file, 'rb');
        if ($handle) {
            while (!feof($handle)) {
                echo fread($handle, 8192);
                flush();
            }
            fclose($handle);
        }
        exit;
    } else {
        fm_set_msg('File not found', 'error');
        fm_redirect(FM_SELF_URL . '?p=' . urlencode(FM_PATH));
    }
}

// 上传
if (isset($_POST['upl'])) {
    check_write_permission();
    
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        echo json_encode(array('status' => 'error', 'info' => 'Invalid security token'));
        exit;
    }
    
    $path = FM_ROOT_PATH;
    if (FM_PATH != '') {
        $path .= '/' . FM_PATH;
    }

    if (!is_writable($path)) {
        echo json_encode(array('status' => 'error', 'info' => 'Directory not writable'));
        exit;
    }

    $allowed_ext = FM_UPLOAD_EXT ? array_map('trim', explode(',', FM_UPLOAD_EXT)) : array();
    $response = array('status' => 'error', 'info' => 'Upload failed');

    $files = $_FILES['upload'] ?? array();
    $fileCount = count($files['name'] ?? array());
    
    for ($i = 0; $i < $fileCount; $i++) {
        $tmp_name = $files['tmp_name'][$i] ?? '';
        $filename = $files['name'][$i] ?? '';
        $error = $files['error'][$i] ?? UPLOAD_ERR_NO_FILE;
        $size = $files['size'][$i] ?? 0;
        
        if ($error === UPLOAD_ERR_OK && !empty($tmp_name) && $tmp_name != 'none' && is_uploaded_file($tmp_name)) {
            if ($size > $max_upload_size_bytes) {
                $response = array('status' => 'error', 'info' => 'File size exceeds limit');
                continue;
            }
            
            $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
            if (!empty($allowed_ext) && $ext != '' && !in_array($ext, $allowed_ext)) {
                $response = array('status' => 'error', 'info' => 'File type not allowed');
                continue;
            }
            
            // 防止文件名中的特殊字符
            $filename = fm_sanitize_filename($filename);
            $target_path = $path . '/' . $filename;
            
            $chunkIndex = isset($_POST['dzchunkindex']) ? (int)$_POST['dzchunkindex'] : null;
            $chunkTotal = isset($_POST['dztotalchunkcount']) ? (int)$_POST['dztotalchunkcount'] : null;
            
            if ($chunkIndex !== null && $chunkTotal !== null) {
                // 分块上传
                $partFile = $target_path . '.part';
                
                if ($chunkIndex == 0 && file_exists($partFile)) {
                    @unlink($partFile);
                }
                
                $out = @fopen($partFile, $chunkIndex == 0 ? 'wb' : 'ab');
                if ($out) {
                    $in = @fopen($tmp_name, 'rb');
                    if ($in) {
                        while ($buff = fread($in, 4096)) {
                            fwrite($out, $buff);
                        }
                        fclose($in);
                        fclose($out);
                        @unlink($tmp_name);
                        
                        if ($chunkIndex == $chunkTotal - 1) {
                            $finalName = $target_path;
                            $counter = 1;
                            $pathInfo = pathinfo($finalName);
                            while (file_exists($finalName)) {
                                $finalName = $pathInfo['dirname'] . '/' . $pathInfo['filename'] . '_' . $counter . '.' . $pathInfo['extension'];
                                $counter++;
                            }
                            
                            if (rename($partFile, $finalName)) {
                                @chmod($finalName, 0644);
                                $response = array('status' => 'success', 'info' => 'Upload successful');
                            } else {
                                $response = array('status' => 'error', 'info' => 'File merge failed');
                            }
                        } else {
                            $response = array('status' => 'success', 'info' => 'Chunk uploaded');
                        }
                    } else {
                        $response = array('status' => 'error', 'info' => 'Cannot read temp file');
                    }
                } else {
                    $response = array('status' => 'error', 'info' => 'Cannot write target file');
                }
            } else {
                // 普通上传 - 处理重名
                $finalName = $target_path;
                $counter = 1;
                $pathInfo = pathinfo($finalName);
                while (file_exists($finalName)) {
                    $finalName = $pathInfo['dirname'] . '/' . $pathInfo['filename'] . '_' . $counter . '.' . $pathInfo['extension'];
                    $counter++;
                }
                
                if (move_uploaded_file($tmp_name, $finalName)) {
                    @chmod($finalName, 0644);
                    $response = array('status' => 'success', 'info' => 'Upload successful');
                } else {
                    $response = array('status' => 'error', 'info' => 'File move failed');
                }
            }
        } else {
            $errorMessages = array(
                UPLOAD_ERR_INI_SIZE => 'File exceeds server limit',
                UPLOAD_ERR_FORM_SIZE => 'File exceeds form limit',
                UPLOAD_ERR_PARTIAL => 'File only partially uploaded',
                UPLOAD_ERR_NO_FILE => 'No file uploaded',
                UPLOAD_ERR_NO_TMP_DIR => 'Temp folder not found',
                UPLOAD_ERR_CANT_WRITE => 'File write failed',
                UPLOAD_ERR_EXTENSION => 'File blocked by extension',
            );
            $response = array('status' => 'error', 'info' => $errorMessages[$error] ?? 'Unknown error');
        }
    }

    header('Content-Type: application/json');
    echo json_encode($response);
    exit;
}

// 批量删除
if (isset($_POST['group'], $_POST['delete'])) {
    check_write_permission();
    
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        fm_set_msg('Invalid security token', 'error');
        fm_redirect(FM_SELF_URL . '?p=' . urlencode(FM_PATH));
    }
    
    $path = FM_ROOT_PATH;
    if (FM_PATH != '') {
        $path .= '/' . FM_PATH;
    }

    $errors = 0;
    $files = $_POST['file'] ?? [];
    
    if (is_array($files) && count($files)) {
        foreach ($files as $f) {
            if ($f != '') {
                $f = fm_clean_path($f);
                $target_path = $path . '/' . $f;
                $real_target = realpath($target_path);
                $real_base = realpath(FM_ROOT_PATH);
                
                if ($real_target !== false && strpos($real_target, $real_base) === 0) {
                    if (!fm_rdelete($real_target)) {
                        $errors++;
                    }
                } else {
                    $errors++;
                }
            }
        }
        
        if ($errors == 0) {
            fm_set_msg('Selected files and folder deleted');
        } else {
            fm_set_msg('Error while deleting items', 'error');
        }
    } else {
        fm_set_msg('Nothing selected', 'alert');
    }

    fm_redirect(FM_SELF_URL . '?p=' . urlencode(FM_PATH));
}

// 打包
if (isset($_POST['group'], $_POST['zip'])) {
    check_write_permission();
    
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        fm_set_msg('Invalid security token', 'error');
        fm_redirect(FM_SELF_URL . '?p=' . urlencode(FM_PATH));
    }
    
    $path = FM_ROOT_PATH;
    if (FM_PATH != '') {
        $path .= '/' . FM_PATH;
    }

    if (!class_exists('ZipArchive')) {
        fm_set_msg('Operations with archives are not available', 'error');
        fm_redirect(FM_SELF_URL . '?p=' . urlencode(FM_PATH));
    }

    $files = $_POST['file'] ?? [];
    if (!empty($files)) {
        chdir($path);

        if (count($files) == 1) {
            $one_file = reset($files);
            $one_file = basename($one_file);
            $zipname = $one_file . '_' . date('Ymd_His') . '.zip';
        } else {
            $zipname = 'archive_' . date('Ymd_His') . '.zip';
        }

        $zipper = new FM_Zipper();
        $res = $zipper->create($zipname, $files);

        if ($res) {
            fm_set_msg(sprintf('Archive <b>%s</b> created', fm_enc($zipname)));
        } else {
            fm_set_msg('Archive not created', 'error');
        }
    } else {
        fm_set_msg('Nothing selected', 'alert');
    }

    fm_redirect(FM_SELF_URL . '?p=' . urlencode(FM_PATH));
}

// 解包
if (isset($_GET['unzip'])) {
    check_write_permission();
    
    $token = $_POST['csrf_token'] ?? $_GET['csrf_token'] ?? '';
    if (!verify_csrf_token($token)) {
        fm_set_msg('Invalid security token', 'error');
        fm_redirect(FM_SELF_URL . '?p=' . urlencode(FM_PATH));
    }
    
    $unzip = fm_clean_path($_GET['unzip']);
    $unzip = str_replace('/', '', $unzip);

    $path = FM_ROOT_PATH;
    if (FM_PATH != '') {
        $path .= '/' . FM_PATH;
    }

    if (!class_exists('ZipArchive')) {
        fm_set_msg('Operations with archives are not available', 'error');
        fm_redirect(FM_SELF_URL . '?p=' . urlencode(FM_PATH));
    }

    if ($unzip != '' && is_file($path . '/' . $unzip)) {
        $zip_path = $path . '/' . $unzip;
        $real_zip = realpath($zip_path);
        $real_base = realpath(FM_ROOT_PATH);
        
        if ($real_zip === false || strpos($real_zip, $real_base) !== 0) {
            fm_set_msg('Invalid file path', 'error');
        } else {
            $tofolder = '';
            if (isset($_GET['tofolder'])) {
                $tofolder = pathinfo($real_zip, PATHINFO_FILENAME);
                if (fm_mkdir($path . '/' . $tofolder, true)) {
                    $path .= '/' . $tofolder;
                }
            }

            $zipper = new FM_Zipper();
            $res = $zipper->unzip($real_zip, $path);

            if ($res) {
                fm_set_msg('Archive unpacked');
            } else {
                fm_set_msg('Archive not unpacked', 'error');
            }
        }
    } else {
        fm_set_msg('File not found', 'error');
    }
    fm_redirect(FM_SELF_URL . '?p=' . urlencode(FM_PATH));
}

// 修改权限
if (isset($_POST['chmod']) && !FM_IS_WIN) {
    check_write_permission();
    
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        fm_set_msg('Invalid security token', 'error');
        fm_redirect(FM_SELF_URL . '?p=' . urlencode(FM_PATH));
    }
    
    $path = FM_ROOT_PATH;
    if (FM_PATH != '') {
        $path .= '/' . FM_PATH;
    }

    $file = fm_clean_path($_POST['chmod']);
    $file = str_replace('/', '', $file);
    
    $file_path = $path . '/' . $file;
    $real_file = realpath($file_path);
    $real_base = realpath(FM_ROOT_PATH);
    
    if ($file == '' || $real_file === false || strpos($real_file, $real_base) !== 0) {
        fm_set_msg('File not found', 'error');
        fm_redirect(FM_SELF_URL . '?p=' . urlencode(FM_PATH));
    }

    $mode = 0;
    if (!empty($_POST['ur'])) $mode |= 0400;
    if (!empty($_POST['uw'])) $mode |= 0200;
    if (!empty($_POST['ux'])) $mode |= 0100;
    if (!empty($_POST['gr'])) $mode |= 0040;
    if (!empty($_POST['gw'])) $mode |= 0020;
    if (!empty($_POST['gx'])) $mode |= 0010;
    if (!empty($_POST['or'])) $mode |= 0004;
    if (!empty($_POST['ow'])) $mode |= 0002;
    if (!empty($_POST['ox'])) $mode |= 0001;

    if (@chmod($real_file, $mode)) {
        fm_set_msg('Permissions changed');
    } else {
        fm_set_msg('Permissions not changed', 'error');
    }

    fm_redirect(FM_SELF_URL . '?p=' . urlencode(FM_PATH));
}

/*************************** /ACTIONS ***************************/

$path = FM_ROOT_PATH;
if (FM_PATH != '') {
    $path .= '/' . FM_PATH;
}

if (!is_dir($path)) {
    fm_redirect(FM_SELF_URL . '?p=');
}

$parent = fm_get_parent_path(FM_PATH);

$objects = is_readable($path) ? scandir($path) : array();
$folders = array();
$files = array();

if (is_array($objects)) {
    foreach ($objects as $file) {
        if ($file == '.' || $file == '..') {
            continue;
        }
        
        if (!FM_SHOW_HIDDEN && substr($file, 0, 1) === '.') {
            continue;
        }
        
        $new_path = $path . '/' . $file;
        
        if (is_excluded($file, $new_path)) {
            continue;
        }
        
        if (is_file($new_path)) {
            $files[] = $file;
        } elseif (is_dir($new_path)) {
            $folders[] = $file;
        }
    }
}

if (!empty($files)) {
    natcasesort($files);
}
if (!empty($folders)) {
    natcasesort($folders);
}

// 上传表单
if (isset($_GET['upload']) && !FM_READONLY) {
    fm_show_header();
    fm_show_nav_path(FM_PATH);
    
    $max_upload_mb = round($max_upload_size_bytes / 1048576, 2);
    $allowed_ext_display = FM_UPLOAD_EXT ?: 'All files';
    ?>
    <div class="path">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:15px">
            <h3 style="margin:0;font-size:18px;font-weight:600">
                <i class="icon-upload"></i> Upload Files
            </h3>
            <a href="?p=<?php echo urlencode(FM_PATH) ?>" style="color:#6b7280"><i class="icon-goback"></i> Back</a>
        </div>
        
        <p class="break-word" style="margin-bottom:15px">
            <strong>Target folder:</strong> <?php echo fm_enc(fm_convert_win(FM_ROOT_PATH . '/' . FM_PATH)) ?><br>
            <strong>Max file size:</strong> <?php echo $max_upload_mb ?> MB<br>
            <strong>Allowed extensions:</strong> <?php echo $allowed_ext_display ?>
        </p>

        <div class="upload-area" id="upload-area">
            <div class="upload-icon">📁</div>
            <div class="upload-text">Click or drag files here to upload</div>
            <div class="upload-hint">Multiple files supported, max <?php echo $max_upload_mb ?> MB per file</div>
            <input type="file" id="file-input" multiple accept="<?php echo fm_get_upload_accept(); ?>">
        </div>

        <div class="upload-queue" id="upload-queue"></div>

        <div class="upload-actions">
            <div class="upload-summary" id="upload-summary">
                Ready
            </div>
            <div class="upload-buttons">
                <button type="button" class="upload-btn-secondary" onclick="window.location.href='?p=<?php echo urlencode(FM_PATH) ?>'">
                    Cancel
                </button>
                <button type="button" class="upload-btn-primary" id="upload-all-btn" onclick="startAllUploads()">
                    Start Upload
                </button>
            </div>
        </div>
    </div>

    <script>
    var UPLOAD_CONFIG = {
        url: window.location.href,
        path: '<?php echo fm_enc(FM_PATH) ?>',
        csrf: '<?php echo get_csrf_token(); ?>',
        chunkSize: 2 * 1024 * 1024,
        maxFileSize: <?php echo $max_upload_size_bytes; ?>,
        allowedExtensions: '<?php echo FM_UPLOAD_EXT; ?>'.split(',').filter(Boolean),
        concurrent: 2,
        retryTimes: 3,
        retryDelay: 1000
    };

    var uploadQueue = [];
    var uploading = false;

    (function() {
        var area = document.getElementById('upload-area');
        var input = document.getElementById('file-input');
        
        area.addEventListener('click', function() { input.click(); });
        input.addEventListener('change', function(e) { addFiles(e.target.files); });
        
        area.addEventListener('dragover', function(e) {
            e.preventDefault();
            area.classList.add('dragover');
        });
        
        area.addEventListener('dragleave', function() {
            area.classList.remove('dragover');
        });
        
        area.addEventListener('drop', function(e) {
            e.preventDefault();
            area.classList.remove('dragover');
            addFiles(e.dataTransfer.files);
        });
    })();

    function addFiles(files) {
        var added = 0, skipped = 0;
        
        for (var i = 0; i < files.length; i++) {
            var file = files[i];
            
            if (file.size > UPLOAD_CONFIG.maxFileSize) {
                showToast('File "' + file.name + '" exceeds size limit', 'error');
                skipped++;
                continue;
            }
            
            if (UPLOAD_CONFIG.allowedExtensions.length > 0) {
                var ext = file.name.split('.').pop().toLowerCase();
                if (!UPLOAD_CONFIG.allowedExtensions.includes(ext)) {
                    showToast('File "' + file.name + '" type not allowed', 'error');
                    skipped++;
                    continue;
                }
            }
            
            if (uploadQueue.find(function(item) { return item.name === file.name; })) {
                showToast('File "' + file.name + '" already in queue', 'error');
                skipped++;
                continue;
            }
            
            uploadQueue.push(createUploadItem(file));
            added++;
        }
        
        if (added > 0) {
            showToast('Added ' + added + ' file(s)' + (skipped > 0 ? ', skipped ' + skipped : ''), 'success');
        }
        
        renderQueue();
        updateSummary();
    }

    function createUploadItem(file) {
        return {
            id: Date.now() + Math.random(),
            file: file,
            name: file.name,
            size: file.size,
            status: 'pending',
            progress: 0,
            chunks: Math.ceil(file.size / UPLOAD_CONFIG.chunkSize),
            retryCount: 0,
            xhr: null
        };
    }

    function formatSize(bytes) {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
        if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
        return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
    }

    function renderQueue() {
        var html = '';
        for (var i = 0; i < uploadQueue.length; i++) {
            var item = uploadQueue[i];
            html += renderUploadItem(item);
        }
        document.getElementById('upload-queue').innerHTML = html;
        
        for (var i = 0; i < uploadQueue.length; i++) {
            (function(item) {
                var container = document.getElementById('upload-item-' + item.id);
                if (!container) return;
                
                var retryBtn = container.querySelector('.upload-retry');
                if (retryBtn) retryBtn.onclick = function() { retryUpload(item.id); };
                
                var cancelBtn = container.querySelector('.upload-cancel');
                if (cancelBtn) cancelBtn.onclick = function() { cancelUpload(item.id); };
                
                var removeBtn = container.querySelector('.upload-remove');
                if (removeBtn) removeBtn.onclick = function() { removeFromQueue(item.id); };
            })(uploadQueue[i]);
        }
    }

    function renderUploadItem(item) {
        var statusClass = '', statusText = '', progressBarClass = '', actions = '';
        
        switch (item.status) {
            case 'pending':
                statusText = 'Waiting';
                actions = '<button class="upload-btn upload-cancel">Cancel</button>';
                break;
            case 'uploading':
                statusClass = 'uploading';
                statusText = 'Uploading ' + item.progress + '%';
                actions = '<button class="upload-btn upload-cancel">Cancel</button>';
                break;
            case 'success':
                statusClass = 'success';
                statusText = 'Complete';
                progressBarClass = 'success';
                actions = '<button class="upload-btn upload-remove">Remove</button>';
                break;
            case 'error':
                statusClass = 'error';
                statusText = 'Failed';
                progressBarClass = 'error';
                actions = '<button class="upload-btn upload-retry retry">Retry</button> ' +
                          '<button class="upload-btn upload-remove">Remove</button>';
                break;
            case 'cancelled':
                statusText = 'Cancelled';
                actions = '<button class="upload-btn upload-retry retry">Retry</button> ' +
                          '<button class="upload-btn upload-remove">Remove</button>';
                break;
        }
        
        var errorHtml = item.error ? '<div class="upload-error-message">' + item.error + '</div>' : '';
        
        return '<div class="upload-item" id="upload-item-' + item.id + '">' +
            '<div class="upload-item-header">' +
                '<span class="upload-item-name" title="' + item.name + '">' + item.name + '</span>' +
                '<div class="upload-item-status">' +
                    '<span class="upload-item-size">' + formatSize(item.size) + '</span>' +
                    '<span class="upload-status-badge ' + statusClass + '">' + statusText + '</span>' +
                '</div>' +
            '</div>' +
            '<div class="upload-progress">' +
                '<div class="upload-progress-bar ' + progressBarClass + '" style="width:' + item.progress + '%"></div>' +
            '</div>' +
            errorHtml +
            '<div class="upload-item-actions">' + actions + '</div>' +
        '</div>';
    }

    function updateSummary() {
        var stats = { total: uploadQueue.length, success: 0, error: 0, uploading: 0, pending: 0 };
        
        for (var i = 0; i < uploadQueue.length; i++) {
            var item = uploadQueue[i];
            if (item.status === 'success') stats.success++;
            else if (item.status === 'error') stats.error++;
            else if (item.status === 'uploading') stats.uploading++;
            else if (item.status === 'pending') stats.pending++;
        }
        
        var summary = document.getElementById('upload-summary');
        var allBtn = document.getElementById('upload-all-btn');
        
        if (stats.uploading > 0) {
            summary.textContent = 'Uploading: ' + stats.success + '/' + stats.total + ' complete';
            allBtn.textContent = 'Uploading...';
            allBtn.disabled = true;
        } else if (stats.pending > 0 || (stats.error > 0 && stats.success + stats.error === stats.total)) {
            summary.textContent = stats.total + ' file(s), ' + stats.success + ' success, ' + stats.error + ' failed';
            allBtn.textContent = stats.error > 0 && stats.pending === 0 ? 'Retry Failed' : 'Start Upload';
            allBtn.disabled = false;
        } else if (stats.success === stats.total && stats.total > 0) {
            summary.textContent = 'All uploads complete! ' + stats.total + ' file(s)';
            allBtn.textContent = 'Complete';
            allBtn.disabled = true;
        } else {
            summary.textContent = 'Ready';
            allBtn.textContent = 'Start Upload';
            allBtn.disabled = uploadQueue.length === 0;
        }
    }

    function startAllUploads() {
        if (uploading) return;
        uploading = true;
        uploadNextBatch();
    }

    function uploadNextBatch() {
        var pending = uploadQueue.filter(function(item) {
            return item.status === 'pending' || 
                   (item.status === 'error' && item.retryCount < UPLOAD_CONFIG.retryTimes);
        });
        
        if (pending.length === 0) {
            uploading = false;
            updateSummary();
            
            var successCount = uploadQueue.filter(function(i) { return i.status === 'success'; }).length;
            var errorCount = uploadQueue.filter(function(i) { return i.status === 'error'; }).length;
            
            if (errorCount > 0) {
                showToast('Upload complete: ' + successCount + ' success, ' + errorCount + ' failed', 'error');
            } else if (successCount > 0) {
                showToast('All uploads successful! ' + successCount + ' file(s)', 'success');
            }
            return;
        }
        
        var batch = pending.slice(0, UPLOAD_CONFIG.concurrent);
        var completed = 0;
        
        function onComplete() {
            completed++;
            if (completed >= batch.length) {
                uploadNextBatch();
            }
        }
        
        for (var i = 0; i < batch.length; i++) {
            uploadFile(batch[i], onComplete);
        }
        
        updateSummary();
    }

    function uploadFile(item, callback) {
        item.status = 'uploading';
        item.progress = 0;
        renderQueue();
        updateSummary();
        
        var currentChunk = 0;
        
        function uploadNextChunk() {
            if (item.status === 'cancelled') {
                callback();
                return;
            }
            
            if (currentChunk >= item.chunks) {
                finalizeUpload();
                return;
            }
            
            var start = currentChunk * UPLOAD_CONFIG.chunkSize;
            var end = Math.min(start + UPLOAD_CONFIG.chunkSize, item.file.size);
            var chunk = item.file.slice(start, end);
            
            var formData = new FormData();
            formData.append('upload[]', chunk, item.file.name);
            formData.append('p', UPLOAD_CONFIG.path);
            formData.append('upl', '1');
            formData.append('csrf_token', UPLOAD_CONFIG.csrf);
            formData.append('dzchunkindex', currentChunk);
            formData.append('dztotalchunkcount', item.chunks);
            
            var xhr = new XMLHttpRequest();
            item.xhr = xhr;
            
            xhr.upload.addEventListener('progress', function(e) {
                if (e.lengthComputable) {
                    var chunkProgress = e.loaded / e.total;
                    var overallProgress = ((currentChunk + chunkProgress) / item.chunks) * 100;
                    item.progress = Math.round(overallProgress);
                    renderQueue();
                }
            });
            
            xhr.addEventListener('load', function() {
                if (xhr.status === 200) {
                    try {
                        var response = JSON.parse(xhr.responseText);
                        if (response.status === 'success') {
                            currentChunk++;
                            uploadNextChunk();
                        } else {
                            handleError(response.info || 'Upload failed');
                        }
                    } catch (e) {
                        handleError('Response parse failed');
                    }
                } else {
                    handleError('HTTP ' + xhr.status);
                }
            });
            
            xhr.addEventListener('error', function() {
                handleError('Network error');
            });
            
            xhr.addEventListener('abort', function() {
                callback();
            });
            
            function handleError(msg) {
                if (item.retryCount < UPLOAD_CONFIG.retryTimes) {
                    item.retryCount++;
                    setTimeout(uploadNextChunk, UPLOAD_CONFIG.retryDelay);
                } else {
                    item.status = 'error';
                    item.error = msg;
                    renderQueue();
                    updateSummary();
                    callback();
                }
            }
            
            xhr.open('POST', UPLOAD_CONFIG.url, true);
            xhr.send(formData);
        }
        
        function finalizeUpload() {
            item.status = 'success';
            item.progress = 100;
            renderQueue();
            updateSummary();
            callback();
        }
        
        uploadNextChunk();
    }

    function retryUpload(id) {
        var item = uploadQueue.find(function(i) { return i.id == id; });
        if (item) {
            item.status = 'pending';
            item.progress = 0;
            item.error = null;
            item.retryCount = 0;
            renderQueue();
            updateSummary();
            if (!uploading) startAllUploads();
        }
    }

    function cancelUpload(id) {
        var item = uploadQueue.find(function(i) { return i.id == id; });
        if (item) {
            if (item.xhr) item.xhr.abort();
            item.status = 'cancelled';
            renderQueue();
            updateSummary();
        }
    }

    function removeFromQueue(id) {
        var index = uploadQueue.findIndex(function(i) { return i.id == id; });
        if (index !== -1) {
            uploadQueue.splice(index, 1);
            renderQueue();
            updateSummary();
        }
    }

    function showToast(message, type) {
        var toast = document.createElement('div');
        toast.className = 'upload-toast' + (type ? ' ' + type : '');
        toast.textContent = message;
        document.body.appendChild(toast);
        
        setTimeout(function() {
            toast.style.opacity = '0';
            setTimeout(function() { toast.remove(); }, 300);
        }, 3000);
    }
    </script>
    <?php
    fm_show_footer();
    exit;
}

// 复制表单 POST
if (isset($_POST['copy']) && !FM_READONLY) {
    $copy_files = $_POST['file'] ?? [];
    if (!is_array($copy_files) || empty($copy_files)) {
        fm_set_msg('Nothing selected', 'alert');
        fm_redirect(FM_SELF_URL . '?p=' . urlencode(FM_PATH));
    }

    fm_show_header();
    fm_show_nav_path(FM_PATH);
    ?>
    <div class="path">
        <p><b>Copying</b></p>
        <form action="" method="post">
            <input type="hidden" name="p" value="<?php echo fm_enc(FM_PATH) ?>">
            <input type="hidden" name="finish" value="1">
            <input type="hidden" name="csrf_token" value="<?php echo fm_enc(get_csrf_token()); ?>">
            <?php
            foreach ($copy_files as $cf) {
                echo '<input type="hidden" name="file[]" value="' . fm_enc($cf) . '">' . PHP_EOL;
            }
            $copy_files_enc = array_map('fm_enc', $copy_files);
            ?>
            <p class="break-word">Files: <b><?php echo implode('</b>, <b>', $copy_files_enc) ?></b></p>
            <p class="break-word">Source folder: <?php echo fm_enc(fm_convert_win(FM_ROOT_PATH . '/' . FM_PATH)) ?><br>
                <label for="inp_copy_to">Destination folder:</label>
                <?php echo FM_ROOT_PATH ?>/<input name="copy_to" id="inp_copy_to" value="<?php echo fm_enc(FM_PATH) ?>" style="padding:5px;width:300px">
            </p>
            <p><label><input type="checkbox" name="move" value="1"> Move</label></p>
            <p>
                <button class="btn" style="padding:8px 20px"><i class="icon-apply"></i> Copy</button> &nbsp;
                <b><a href="?p=<?php echo urlencode(FM_PATH) ?>"><i class="icon-cancel"></i> Cancel</a></b>
            </p>
        </form>
    </div>
    <?php
    fm_show_footer();
    exit;
}

// 复制表单 GET
if (isset($_GET['copy']) && !isset($_GET['finish']) && !FM_READONLY) {
    $copy = fm_clean_path($_GET['copy']);
    if ($copy == '' || !file_exists(FM_ROOT_PATH . '/' . $copy)) {
        fm_set_msg('File not found', 'error');
        fm_redirect(FM_SELF_URL . '?p=' . urlencode(FM_PATH));
    }

    fm_show_header();
    fm_show_nav_path(FM_PATH);
    ?>
    <div class="path">
        <p><b>Copying</b></p>
        <p class="break-word">
            Source path: <?php echo fm_enc(fm_convert_win(FM_ROOT_PATH . '/' . $copy)) ?><br>
            Destination folder: <?php echo fm_enc(fm_convert_win(FM_ROOT_PATH . '/' . FM_PATH)) ?>
        </p>
        <p>
            <b><a href="?p=<?php echo urlencode(FM_PATH) ?>&amp;copy=<?php echo urlencode($copy) ?>&amp;finish=1&amp;csrf_token=<?php echo urlencode(get_csrf_token()); ?>" onclick="return confirm('Copy this item?')"><i class="icon-apply"></i> Copy</a></b> &nbsp;
            <b><a href="?p=<?php echo urlencode(FM_PATH) ?>&amp;copy=<?php echo urlencode($copy) ?>&amp;finish=1&amp;move=1&amp;csrf_token=<?php echo urlencode(get_csrf_token()); ?>" onclick="return confirm('Move this item?')"><i class="icon-apply"></i> Move</a></b> &nbsp;
            <b><a href="?p=<?php echo urlencode(FM_PATH) ?>"><i class="icon-cancel"></i> Cancel</a></b>
        </p>
        <p><i>Select folder:</i></p>
        <ul class="folders break-word">
            <?php
            if ($parent !== false) {
                ?>
                <li><a href="?p=<?php echo urlencode($parent) ?>&amp;copy=<?php echo urlencode($copy) ?>"><i class="icon-arrow_up"></i> ..</a></li>
            <?php
            }
            foreach ($folders as $f) {
                ?>
                <li><a href="?p=<?php echo urlencode(trim(FM_PATH . '/' . $f, '/')) ?>&amp;copy=<?php echo urlencode($copy) ?>"><i class="icon-folder"></i> <?php echo fm_enc(fm_convert_win($f)) ?></a></li>
            <?php
            }
            ?>
        </ul>
    </div>
    <?php
    fm_show_footer();
    exit;
}

// 文件查看器
if (isset($_GET['view'])) {
    $file = fm_clean_path($_GET['view']);
    $file = str_replace('/', '', $file);
    $file_path = $path . '/' . $file;
    $real_file = realpath($file_path);
    $real_base = realpath(FM_ROOT_PATH);
    
    if ($file == '' || $real_file === false || strpos($real_file, $real_base) !== 0 || !is_file($real_file)) {
        fm_set_msg('File not found', 'error');
        fm_redirect(FM_SELF_URL . '?p=' . urlencode(FM_PATH));
    }

    fm_show_header();
    fm_show_nav_path(FM_PATH);

    $file_url = FM_ROOT_URL . fm_convert_win((FM_PATH != '' ? '/' . FM_PATH : '') . '/' . $file);
    $ext = strtolower(pathinfo($real_file, PATHINFO_EXTENSION));
    $mime_type = fm_get_mime_type($real_file);
    $filesize = filesize($real_file);
    
    $display_path = fm_get_display_path($real_file);

    $is_zip = false;
    $is_image = false;
    $is_audio = false;
    $is_video = false;
    $is_text = false;
    $is_onlineViewer = false;

    $view_title = 'File';
    $filenames = false;
    $content = '';
    
    if ($online_viewer && $online_viewer !== 'false' && in_array($ext, array('doc', 'docx', 'xls', 'xlsx', 'pdf', 'ppt', 'pptx'))) {
        $is_onlineViewer = true;
        $view_title = 'Document';
    } elseif ($ext == 'zip') {
        $is_zip = true;
        $view_title = 'Archive';
        $filenames = fm_get_zif_info($real_file);
    } elseif (in_array($ext, fm_get_image_exts())) {
        $is_image = true;
        $view_title = 'Image';
    } elseif (in_array($ext, fm_get_audio_exts())) {
        $is_audio = true;
        $view_title = 'Audio';
    } elseif (in_array($ext, fm_get_video_exts())) {
        $is_video = true;
        $view_title = 'Video';
    } elseif (in_array($ext, fm_get_text_exts()) || substr($mime_type, 0, 4) == 'text' || in_array($mime_type, fm_get_text_mimes())) {
        $is_text = true;
        $view_title = 'Text';
        // 限制文本预览大小 (10MB)
        if ($filesize <= 10485760) {
            $content = file_get_contents($real_file);
        } else {
            $content = '[File too large to preview]';
        }
    }

    ?>
    <div class="path">
        <p class="break-word"><b><?php echo $view_title ?> "<?php echo fm_enc(fm_convert_win($file)) ?>"</b></p>
        <p class="break-word">
            <?php echo $display_path['label']; ?>: <?php echo $display_path['path']; ?><br>
            File size: <?php echo fm_get_filesize($filesize) ?><?php if ($filesize >= 1000): ?> (<?php echo sprintf('%s bytes', $filesize) ?>)<?php endif; ?><br>
            MIME-type: <?php echo $mime_type ?><br>
            Modified: <?php echo date(FM_DATETIME_FORMAT, filemtime($real_file)); ?><br>
            <?php
            if ($is_zip && $filenames !== false) {
                $total_files = 0;
                $total_comp = 0;
                $total_uncomp = 0;
                foreach ($filenames as $fn) {
                    if (!$fn['folder']) $total_files++;
                    $total_comp += $fn['compressed_size'];
                    $total_uncomp += $fn['filesize'];
                }
                ?>
                Files in archive: <?php echo $total_files ?><br>
                Total size: <?php echo fm_get_filesize($total_uncomp) ?><br>
                Size in archive: <?php echo fm_get_filesize($total_comp) ?><br>
                Compression: <?php echo $total_uncomp > 0 ? round(($total_comp / $total_uncomp) * 100) : 0 ?>%<br>
                <?php
            }
            if ($is_image) {
                $image_size = @getimagesize($real_file);
                if ($image_size) {
                    echo 'Image dimensions: ' . $image_size[0] . ' x ' . $image_size[1] . '<br>';
                }
            }
            if ($is_text && $content !== '[File too large to preview]') {
                $is_utf8 = fm_is_utf8($content);
                echo 'Charset: ' . ($is_utf8 ? 'utf-8' : '8 bit') . '<br>';
            }
            ?>
        </p>
        <p>
            <form method="post" style="display:inline" action="?p=<?php echo urlencode(FM_PATH) ?>&amp;dl=<?php echo urlencode($file) ?>">
                <input type="hidden" name="csrf_token" value="<?php echo fm_enc(get_csrf_token()); ?>">
                <button type="submit" class="btn"><i class="icon-download"></i> Download</button>
            </form> &nbsp;
            <b><a href="<?php echo fm_enc($file_url) ?>" target="_blank" rel="noopener noreferrer"><i class="icon-chain"></i> Open</a></b> &nbsp;
            <?php if (!FM_READONLY): ?>
                <b><a href="?p=<?php echo urlencode(FM_PATH) ?>&amp;del=<?php echo urlencode($file) ?>" onclick="return confirm('Delete this file?');"><i class="icon-cross"></i> Delete</a></b> &nbsp;
                <b><a href="#" onclick="rename('<?php echo fm_enc(FM_PATH) ?>', '<?php echo fm_enc($file) ?>');return false;"><i class="icon-rename"></i> Rename</a></b> &nbsp;
            <?php endif; ?>
            <?php
            if ($is_zip && $filenames !== false && !FM_READONLY) {
                ?>
                <b><a href="?p=<?php echo urlencode(FM_PATH) ?>&amp;unzip=<?php echo urlencode($file) ?>&amp;csrf_token=<?php echo urlencode(get_csrf_token()); ?>" onclick="return confirm('Unpack archive?')"><i class="icon-apply"></i> Unpack</a></b> &nbsp;
                <b><a href="?p=<?php echo urlencode(FM_PATH) ?>&amp;unzip=<?php echo urlencode($file) ?>&amp;tofolder=1&amp;csrf_token=<?php echo urlencode(get_csrf_token()); ?>" onclick="return confirm('Unpack to folder?')"><i class="icon-apply"></i> Unpack to folder</a></b> &nbsp;
                <?php
            }
            ?>
            <b><a href="?p=<?php echo urlencode(FM_PATH) ?>"><i class="icon-goback"></i> Back</a></b>
        </p>
        <?php
        if ($is_onlineViewer) {
            if ($online_viewer == 'google') {
                echo '<iframe src="https://docs.google.com/viewer?embedded=true&url=' . urlencode($file_url) . '" frameborder="0" style="width:100%;min-height:460px" sandbox="allow-scripts allow-same-origin allow-popups"></iframe>';
            } elseif ($online_viewer == 'microsoft') {
                echo '<iframe src="https://view.officeapps.live.com/op/embed.aspx?src=' . urlencode($file_url) . '" frameborder="0" style="width:100%;min-height:460px" sandbox="allow-scripts allow-same-origin allow-popups"></iframe>';
            }
        } elseif ($is_zip) {
            if ($filenames !== false) {
                echo '<code class="maxheight">';
                foreach ($filenames as $fn) {
                    if ($fn['folder']) {
                        echo '<b>' . fm_enc($fn['name']) . '</b><br>';
                    } else {
                        echo fm_enc($fn['name']) . ' (' . fm_get_filesize($fn['filesize']) . ')<br>';
                    }
                }
                echo '</code>';
            } else {
                echo '<p>Error while fetching archive info</p>';
            }
        } elseif ($is_image) {
            echo '<p><img src="' . fm_enc($file_url) . '" alt="" class="preview-img" loading="lazy"></p>';
        } elseif ($is_audio) {
            echo '<p><audio src="' . fm_enc($file_url) . '" controls preload="metadata"></audio></p>';
        } elseif ($is_video) {
            echo '<div class="preview-video"><video src="' . fm_enc($file_url) . '" width="640" height="360" controls preload="metadata"></video></div>';
        } elseif ($is_text) {
            if ($content === '[File too large to preview]') {
                echo '<p><em>File too large to preview. Please download to view.</em></p>';
            } elseif (FM_USE_HIGHLIGHTJS) {
                $hljs_classes = array(
                    'shtml' => 'xml', 'htaccess' => 'apache', 'phtml' => 'php',
                    'lock' => 'json', 'svg' => 'xml', 'js' => 'javascript',
                    'css' => 'css', 'html' => 'html', 'php' => 'php',
                );
                $hljs_class = isset($hljs_classes[$ext]) ? 'lang-' . $hljs_classes[$ext] : 'lang-' . $ext;
                if (empty($ext) || in_array(strtolower($file), fm_get_text_names()) || preg_match('#\.min\.(css|js)$#i', $file)) {
                    $hljs_class = 'nohighlight';
                }
                $content = '<pre class="with-hljs"><code class="' . $hljs_class . '">' . fm_enc($content) . '</code></pre>';
            } elseif (in_array($ext, array('php', 'php4', 'php5', 'phtml', 'phps'))) {
                $content = highlight_string($content, true);
            } else {
                $content = '<pre>' . fm_enc($content) . '</pre>';
            }
            echo $content;
        }
        ?>
    </div>
    <?php
    fm_show_footer();
    exit;
}

// 修改权限页面
if (isset($_GET['chmod']) && !FM_IS_WIN && !FM_READONLY) {
    $file = fm_clean_path($_GET['chmod']);
    $file = str_replace('/', '', $file);
    $file_path = $path . '/' . $file;
    $real_file = realpath($file_path);
    $real_base = realpath(FM_ROOT_PATH);
    
    if ($file == '' || $real_file === false || strpos($real_file, $real_base) !== 0) {
        fm_set_msg('File not found', 'error');
        fm_redirect(FM_SELF_URL . '?p=' . urlencode(FM_PATH));
    }

    fm_show_header();
    fm_show_nav_path(FM_PATH);

    $mode = fileperms($real_file);
    $display_path = fm_get_display_path($real_file);

    ?>
    <div class="path">
        <p><b>Change Permissions</b></p>
        <p><?php echo $display_path['label']; ?>: <?php echo $display_path['path']; ?><br></p>
        <form action="" method="post">
            <input type="hidden" name="p" value="<?php echo fm_enc(FM_PATH) ?>">
            <input type="hidden" name="chmod" value="<?php echo fm_enc($file) ?>">
            <input type="hidden" name="csrf_token" value="<?php echo fm_enc(get_csrf_token()); ?>">

            <table class="compact-table">
                <tr><td></td><td><b>Owner</b></td><td><b>Group</b></td><td><b>Other</b></td></tr>
                <tr>
                    <td style="text-align: right"><b>Read</b></td>
                    <td><label><input type="checkbox" name="ur" value="1"<?php echo ($mode & 0400) ? ' checked' : '' ?>></label></td>
                    <td><label><input type="checkbox" name="gr" value="1"<?php echo ($mode & 0040) ? ' checked' : '' ?>></label></td>
                    <td><label><input type="checkbox" name="or" value="1"<?php echo ($mode & 0004) ? ' checked' : '' ?>></label></td>
                </tr>
                <tr>
                    <td style="text-align: right"><b>Write</b></td>
                    <td><label><input type="checkbox" name="uw" value="1"<?php echo ($mode & 0200) ? ' checked' : '' ?>></label></td>
                    <td><label><input type="checkbox" name="gw" value="1"<?php echo ($mode & 0020) ? ' checked' : '' ?>></label></td>
                    <td><label><input type="checkbox" name="ow" value="1"<?php echo ($mode & 0002) ? ' checked' : '' ?>></label></td>
                </tr>
                <tr>
                    <td style="text-align: right"><b>Execute</b></td>
                    <td><label><input type="checkbox" name="ux" value="1"<?php echo ($mode & 0100) ? ' checked' : '' ?>></label></td>
                    <td><label><input type="checkbox" name="gx" value="1"<?php echo ($mode & 0010) ? ' checked' : '' ?>></label></td>
                    <td><label><input type="checkbox" name="ox" value="1"<?php echo ($mode & 0001) ? ' checked' : '' ?>></label></td>
                </tr>
            </table>

            <p>
                <button class="btn" style="padding:8px 20px"><i class="icon-apply"></i> Change</button> &nbsp;
                <b><a href="?p=<?php echo urlencode(FM_PATH) ?>"><i class="icon-cancel"></i> Cancel</a></b>
            </p>
        </form>
    </div>
    <?php
    fm_show_footer();
    exit;
}

// --- 主界面 ---
fm_show_header();
fm_show_nav_path(FM_PATH);
fm_show_message();

$num_files = count($files);
$num_folders = count($folders);
$all_files_size = 0;
?>
<form action="" method="post" id="main-form">
<input type="hidden" name="p" value="<?php echo fm_enc(FM_PATH) ?>">
<input type="hidden" name="group" value="1">
<input type="hidden" name="csrf_token" value="<?php echo fm_enc(get_csrf_token()); ?>">
<table>
<tr>
<th style="width:3%"><label><input type="checkbox" title="Invert selection" onclick="checkbox_toggle()"></label></th>
<th>Name</th><th style="width:10%">Size</th>
<th style="width:12%">Modified</th>
<?php if (!FM_IS_WIN && !FM_HIDE_COLS): ?><th style="width:6%">Perms</th><th style="width:10%">Owner</th><?php endif; ?>
<th style="width:13%"></th></tr>
<?php
if ($parent !== false) {
    ?>
<tr><td></td><td colspan="<?php echo (!FM_IS_WIN && !FM_HIDE_COLS) ? '6' : '4' ?>"><a href="?p=<?php echo urlencode($parent) ?>"><i class="icon-arrow_up"></i> ..</a></td></tr>
<?php
}

foreach ($folders as $f) {
    $is_link = is_link($path . '/' . $f);
    $img = $is_link ? 'icon-link_folder' : 'icon-folder';
    $modif = date(FM_DATETIME_FORMAT, filemtime($path . '/' . $f));
    $perms = substr(decoct(fileperms($path . '/' . $f)), -4);
    
    if (function_exists('posix_getpwuid') && function_exists('posix_getgrgid')) {
        $owner = @posix_getpwuid(fileowner($path . '/' . $f)) ?: array('name' => '?');
        $group = @posix_getgrgid(filegroup($path . '/' . $f)) ?: array('name' => '?');
    } else {
        $owner = array('name' => '?');
        $group = array('name' => '?');
    }
    ?>
<tr>
<td><label><input type="checkbox" name="file[]" value="<?php echo fm_enc($f) ?>"></label></td>
<td><div class="filename"><a href="?p=<?php echo urlencode(trim(FM_PATH . '/' . $f, '/')) ?>"><i class="<?php echo $img ?>"></i> <?php echo fm_enc(fm_convert_win($f)) ?></a><?php echo ($is_link ? ' &rarr; <i>' . fm_enc(readlink($path . '/' . $f)) . '</i>' : '') ?></div></td>
<td>Folder</td><td><?php echo $modif ?></td>
<?php if (!FM_IS_WIN && !FM_HIDE_COLS): ?>
<td><?php if (!FM_READONLY): ?><a title="Change Permissions" href="?p=<?php echo urlencode(FM_PATH) ?>&amp;chmod=<?php echo urlencode($f) ?>"><?php echo $perms ?></a><?php else: ?><?php echo $perms ?><?php endif; ?></td>
<td><?php echo fm_enc($owner['name'] . ':' . $group['name']) ?></td>
<?php endif; ?>
<td style="white-space:nowrap">
<?php if (!FM_READONLY): ?>
<a title="Delete folder" href="?p=<?php echo urlencode(FM_PATH) ?>&amp;del=<?php echo urlencode($f) ?>" onclick="return confirm('Delete this folder?');" style="display:inline-flex;align-items:center;gap:2px;margin-right:6px;color:#dc2626"><i class="icon-cross"></i></a>
<a title="Rename" href="#" onclick="rename('<?php echo fm_enc(FM_PATH) ?>', '<?php echo fm_enc($f) ?>');return false;" style="display:inline-flex;align-items:center;gap:2px;margin-right:6px;color:#2563eb"><i class="icon-rename"></i></a>
<a title="Copy to..." href="?p=&amp;copy=<?php echo urlencode(trim(FM_PATH . '/' . $f, '/')) ?>" style="display:inline-flex;align-items:center;gap:2px;margin-right:6px;color:#059669"><i class="icon-copy"></i></a>
<?php endif; ?>
<a title="Direct link" href="<?php echo fm_enc(FM_ROOT_URL . (FM_PATH != '' ? '/' . FM_PATH : '') . '/' . $f . '/') ?>" target="_blank" rel="noopener noreferrer" style="display:inline-flex;align-items:center;gap:2px;color:#6b7280"><i class="icon-chain"></i></a>
</td></tr>
    <?php
    flush();
}

foreach ($files as $f) {
    $is_link = is_link($path . '/' . $f);
    $img = $is_link ? 'icon-link_file' : fm_get_file_icon_class($path . '/' . $f);
    $modif = date(FM_DATETIME_FORMAT, filemtime($path . '/' . $f));
    $filesize_raw = filesize($path . '/' . $f);
    $filesize = fm_get_filesize($filesize_raw);
    $filelink = '?p=' . urlencode(FM_PATH) . '&view=' . urlencode($f);
    $all_files_size += $filesize_raw;
    $perms = substr(decoct(fileperms($path . '/' . $f)), -4);
    
    if (function_exists('posix_getpwuid') && function_exists('posix_getgrgid')) {
        $owner = @posix_getpwuid(fileowner($path . '/' . $f)) ?: array('name' => '?');
        $group = @posix_getgrgid(filegroup($path . '/' . $f)) ?: array('name' => '?');
    } else {
        $owner = array('name' => '?');
        $group = array('name' => '?');
    }
    ?>
<tr>
<td><label><input type="checkbox" name="file[]" value="<?php echo fm_enc($f) ?>"></label></td>
<td><div class="filename"><a href="<?php echo fm_enc($filelink) ?>" title="File info"><i class="<?php echo $img ?>"></i> <?php echo fm_enc(fm_convert_win($f)) ?></a><?php echo ($is_link ? ' &rarr; <i>' . fm_enc(readlink($path . '/' . $f)) . '</i>' : '') ?></div></td>
<td><span class="gray" title="<?php printf('%s bytes', $filesize_raw) ?>"><?php echo $filesize ?></span></td>
<td><?php echo $modif ?></td>
<?php if (!FM_IS_WIN && !FM_HIDE_COLS): ?>
<td><?php if (!FM_READONLY): ?><a title="Change Permissions" href="?p=<?php echo urlencode(FM_PATH) ?>&amp;chmod=<?php echo urlencode($f) ?>"><?php echo $perms ?></a><?php else: ?><?php echo $perms ?><?php endif; ?></td>
<td><?php echo fm_enc($owner['name'] . ':' . $group['name']) ?></td>
<?php endif; ?>
<td style="white-space:nowrap">
<?php if (!FM_READONLY): ?>
<a title="Delete file" href="?p=<?php echo urlencode(FM_PATH) ?>&amp;del=<?php echo urlencode($f) ?>" onclick="return confirm('Delete this file?');" style="display:inline-flex;align-items:center;gap:2px;margin-right:6px;color:#dc2626"><i class="icon-cross"></i></a>
<a title="Rename" href="#" onclick="rename('<?php echo fm_enc(FM_PATH) ?>', '<?php echo fm_enc($f) ?>');return false;" style="display:inline-flex;align-items:center;gap:2px;margin-right:6px;color:#2563eb"><i class="icon-rename"></i></a>
<a title="Copy to..." href="?p=<?php echo urlencode(FM_PATH) ?>&amp;copy=<?php echo urlencode(trim(FM_PATH . '/' . $f, '/')) ?>" style="display:inline-flex;align-items:center;gap:2px;margin-right:6px;color:#059669"><i class="icon-copy"></i></a>
<?php endif; ?>
<a title="Direct link" href="<?php echo fm_enc(FM_ROOT_URL . (FM_PATH != '' ? '/' . FM_PATH : '') . '/' . $f) ?>" target="_blank" rel="noopener noreferrer" style="display:inline-flex;align-items:center;gap:2px;margin-right:6px;color:#6b7280"><i class="icon-chain"></i></a>
<form method="post" style="display:inline" action="?p=<?php echo urlencode(FM_PATH) ?>&amp;dl=<?php echo urlencode($f) ?>">
<input type="hidden" name="csrf_token" value="<?php echo fm_enc(get_csrf_token()); ?>">
<button type="submit" title="Download" style="display:inline-flex;align-items:center;gap:2px;padding:0;background:none;border:none;color:#2563eb;cursor:pointer"><i class="icon-download"></i></button>
</form>
</td></tr>
    <?php
    flush();
}

if (empty($folders) && empty($files)) {
    ?>
<tr><td></td><td colspan="<?php echo (!FM_IS_WIN && !FM_HIDE_COLS) ? '6' : '4' ?>"><em>Folder is empty</em></td></tr>
<?php
} else {
    ?>
<tr><td class="gray"></td><td class="gray" colspan="<?php echo (!FM_IS_WIN && !FM_HIDE_COLS) ? '6' : '4' ?>">
Total size: <span title="<?php printf('%s bytes', $all_files_size) ?>"><?php echo fm_get_filesize($all_files_size) ?></span>,
files: <?php echo $num_files ?>,
folders: <?php echo $num_folders ?>
</td></tr>
<?php
}
?>
</table>

<p class="path" style="display:flex;flex-wrap:wrap;align-items:center;gap:8px">
<a href="?p=" title="Root directory" style="display:inline-flex;align-items:center;gap:4px;padding:4px 10px;background:#f3f4f6;border-radius:4px"><i class="icon-home"></i> Root</a>
<span style="color:#d1d5db">|</span>
<a href="#" onclick="select_all();return false;" style="display:inline-flex;align-items:center;gap:4px;padding:4px 10px"><i class="icon-checkbox"></i> Select All</a>
<a href="#" onclick="unselect_all();return false;" style="display:inline-flex;align-items:center;gap:4px;padding:4px 10px"><i class="icon-checkbox_uncheck"></i> Deselect All</a>
<a href="#" onclick="invert_all();return false;" style="display:inline-flex;align-items:center;gap:4px;padding:4px 10px"><i class="icon-checkbox_invert"></i> Invert</a>
<?php if (!FM_READONLY): ?>
<span style="color:#d1d5db">|</span>
<a href="#" onclick="newfolder('<?php echo fm_enc(FM_PATH) ?>');return false;" style="display:inline-flex;align-items:center;gap:4px;padding:4px 10px;background:#dcfce7;color:#166534;border-radius:4px"><i class="icon-folder_add"></i> New Folder</a>
<a href="#" onclick="newfile('<?php echo fm_enc(FM_PATH) ?>');return false;" style="display:inline-flex;align-items:center;gap:4px;padding:4px 10px;background:#fef3c7;color:#92400e;border-radius:4px"><i class="icon-document"></i> New File</a>
<a href="?p=<?php echo urlencode(FM_PATH) ?>&amp;upload" style="display:inline-flex;align-items:center;gap:4px;padding:4px 10px;background:#e0f2fe;color:#0369a1;border-radius:4px"><i class="icon-upload"></i> Upload</a>
<?php endif; ?>
</p>

<?php if (!FM_READONLY): ?>
<p style="display:flex;gap:8px;margin-top:10px">
<button type="submit" name="delete" onclick="return confirm('Delete selected items?')" style="display:inline-flex;align-items:center;gap:4px;padding:6px 16px;background:#fee2e2;color:#991b1b;border:1px solid #fecaca;border-radius:6px;cursor:pointer"><i class="icon-cross"></i> Delete Selected</button>
<button type="submit" name="zip" onclick="return confirm('Create archive?')" style="display:inline-flex;align-items:center;gap:4px;padding:6px 16px;background:#f3f4f6;border:1px solid #d1d5db;border-radius:6px;cursor:pointer"><i class="icon-file_zip"></i> Pack as ZIP</button>
<button type="submit" name="copy" style="display:inline-flex;align-items:center;gap:4px;padding:6px 16px;background:#f3f4f6;border:1px solid #d1d5db;border-radius:6px;cursor:pointer"><i class="icon-copy"></i> Copy Selected</button>
</p>
<?php endif; ?>

</form>

<?php
fm_show_footer();

// --- 函数定义 ---

function getClientIP() {
    $headers = ['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_CLIENT_IP', 'REMOTE_ADDR'];
    foreach ($headers as $header) {
        if (!empty($_SERVER[$header])) {
            $ip = $_SERVER[$header];
            if (strpos($ip, ',') !== false) {
                $ips = explode(',', $ip);
                $ip = trim($ips[0]);
            }
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                return $ip;
            }
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }
        }
    }
    return '0.0.0.0';
}

function fm_sanitize_filename($filename) {
    // 移除路径信息
    $filename = basename($filename);
    // 替换危险字符
    $filename = preg_replace('/[^\p{L}\p{N}\s\._-]/u', '', $filename);
    // 防止多个点
    $filename = preg_replace('/\.{2,}/', '.', $filename);
    // 移除首尾空格和点
    $filename = trim($filename, " \t\n\r\0\x0B.");
    // 防止空文件名
    if (empty($filename) || $filename === '.htaccess' || $filename === '.htpasswd') {
        $filename = 'file_' . date('Ymd_His');
    }
    // 长度限制
    if (strlen($filename) > 255) {
        $filename = substr($filename, 0, 255);
    }
    return $filename;
}

function fm_rdelete($path) {
    if (is_link($path)) {
        return unlink($path);
    } elseif (is_dir($path)) {
        $objects = scandir($path);
        $ok = true;
        if (is_array($objects)) {
            foreach ($objects as $file) {
                if ($file != '.' && $file != '..') {
                    if (!fm_rdelete($path . '/' . $file)) {
                        $ok = false;
                    }
                }
            }
        }
        return ($ok) ? rmdir($path) : false;
    } elseif (is_file($path)) {
        return unlink($path);
    }
    return false;
}

function fm_rename($old, $new) {
    return (!file_exists($new) && file_exists($old)) ? rename($old, $new) : null;
}

function fm_rcopy($path, $dest, $upd = true, $force = true) {
    if (is_dir($path)) {
        if (!fm_mkdir($dest, $force)) {
            return false;
        }
        $objects = scandir($path);
        $ok = true;
        if (is_array($objects)) {
            foreach ($objects as $file) {
                if ($file != '.' && $file != '..') {
                    if (!fm_rcopy($path . '/' . $file, $dest . '/' . $file, $upd, $force)) {
                        $ok = false;
                    }
                }
            }
        }
        return $ok;
    } elseif (is_file($path)) {
        return fm_copy($path, $dest, $upd);
    }
    return false;
}

function fm_mkdir($dir, $force) {
    if (file_exists($dir)) {
        if (is_dir($dir)) {
            return $dir;
        } elseif (!$force) {
            return false;
        }
        unlink($dir);
    }
    return mkdir($dir, 0755, true);
}

function fm_copy($f1, $f2, $upd) {
    $time1 = filemtime($f1);
    if (file_exists($f2)) {
        $time2 = filemtime($f2);
        if ($time2 >= $time1 && $upd) {
            return false;
        }
    }
    $ok = copy($f1, $f2);
    if ($ok) {
        touch($f2, $time1);
    }
    return $ok;
}

function fm_get_mime_type($file_path) {
    if (function_exists('finfo_open')) {
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $mime = finfo_file($finfo, $file_path);
        finfo_close($finfo);
        return $mime;
    } elseif (function_exists('mime_content_type')) {
        return mime_content_type($file_path);
    }
    
    // 回退到扩展名映射
    $ext = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
    $mime_map = array(
        'jpg' => 'image/jpeg', 'jpeg' => 'image/jpeg', 'png' => 'image/png',
        'gif' => 'image/gif', 'pdf' => 'application/pdf', 'txt' => 'text/plain',
        'html' => 'text/html', 'htm' => 'text/html', 'php' => 'text/plain',
        'js' => 'application/javascript', 'css' => 'text/css',
        'zip' => 'application/zip', 'json' => 'application/json',
    );
    return $mime_map[$ext] ?? 'application/octet-stream';
}

function fm_redirect($url, $code = 302) {
    header('Location: ' . $url, true, $code);
    exit;
}

function fm_clean_path($path) {
    $path = trim($path);
    $path = trim($path, '\\/');
    $path = str_replace(array('../', '..\\', "\0", "\r", "\n"), '', $path);
    if ($path == '..') {
        $path = '';
    }
    return str_replace('\\', '/', $path);
}

function fm_get_parent_path($path) {
    $path = fm_clean_path($path);
    if ($path != '') {
        $array = explode('/', $path);
        if (count($array) > 1) {
            $array = array_slice($array, 0, -1);
            return implode('/', $array);
        }
        return '';
    }
    return false;
}

function fm_get_display_path($file_path) {
    global $path_display_mode, $root_path, $root_url;
    
    switch ($path_display_mode) {
        case 'relative':
            return array(
                'label' => 'Path',
                'path' => fm_enc(fm_convert_win(str_replace($root_path, '', $file_path)))
            );
        case 'host':
            $relative_path = str_replace($root_path, '', $file_path);
            return array(
                'label' => 'Host Path',
                'path' => fm_enc(fm_convert_win('/' . $root_url . '/' . ltrim(str_replace('\\', '/', $relative_path), '/')))
            );
        default:
            return array(
                'label' => 'Full Path',
                'path' => fm_enc(fm_convert_win($file_path))
            );
    }
}

function fm_get_filesize($size) {
    $units = array('B', 'KB', 'MB', 'GB', 'TB');
    $power = $size > 0 ? floor(log($size, 1024)) : 0;
    $power = min($power, count($units) - 1);
    return sprintf('%s %s', round($size / pow(1024, $power), 2), $units[$power]);
}

function fm_get_zif_info($path) {
    if (class_exists('ZipArchive')) {
        $zip = new ZipArchive();
        if ($zip->open($path) === true) {
            $filenames = array();
            for ($i = 0; $i < $zip->numFiles; $i++) {
                $stat = $zip->statIndex($i);
                $filenames[] = array(
                    'name' => $stat['name'],
                    'filesize' => $stat['size'],
                    'compressed_size' => $stat['comp_size'],
                    'folder' => substr($stat['name'], -1) == '/'
                );
            }
            $zip->close();
            return $filenames;
        }
    }
    return false;
}

function fm_enc($text) {
    return htmlspecialchars($text ?? '', ENT_QUOTES, 'UTF-8');
}

function fm_set_msg($msg, $status = 'ok') {
    $_SESSION['message'] = $msg;
    $_SESSION['status'] = $status;
}

function fm_is_utf8($string) {
    return preg_match('//u', $string);
}

function fm_convert_win($filename) {
    if (FM_IS_WIN && function_exists('iconv')) {
        $filename = iconv(FM_ICONV_INPUT_ENC, 'UTF-8//IGNORE', $filename);
    }
    return $filename;
}

function fm_get_file_icon_class($path) {
    $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
    
    $icons = [
        'image' => ['ico', 'gif', 'jpg', 'jpeg', 'jpc', 'jp2', 'jpx', 'xbm', 'wbmp', 'png', 'bmp', 'tif', 'tiff', 'webp', 'avif', 'svg'],
        'text' => ['txt', 'css', 'ini', 'conf', 'log', 'htaccess', 'passwd', 'sql', 'js', 'json', 'sh', 'config', 'md', 'yml', 'yaml'],
        'zip' => ['zip', 'rar', 'gz', 'tar', '7z', 'bz2'],
        'php' => ['php', 'php4', 'php5', 'phps', 'phtml'],
        'html' => ['htm', 'html', 'shtml', 'xhtml'],
        'code' => ['xml', 'xsl', 'xsd'],
        'music' => ['wav', 'mp3', 'mp2', 'm4a', 'aac', 'ogg', 'oga', 'wma', 'flac'],
        'film' => ['avi', 'mpg', 'mpeg', 'mp4', 'm4v', 'flv', 'f4v', 'mov', 'mkv', 'webm'],
        'pdf' => ['pdf'],
        'excel' => ['xls', 'xlsx', 'csv'],
        'word' => ['doc', 'docx'],
    ];
    
    foreach ($icons as $icon => $exts) {
        if (in_array($ext, $exts)) {
            return 'icon-file_' . $icon;
        }
    }
    
    return 'icon-document';
}

function fm_get_image_exts() {
    return array('ico', 'gif', 'jpg', 'jpeg', 'jpc', 'jp2', 'jpx', 'xbm', 'wbmp', 'png', 'bmp', 'tif', 'tiff', 'webp', 'avif', 'svg');
}

function fm_get_video_exts() {
    return array('webm', 'mp4', 'm4v', 'ogm', 'ogv', 'mov', 'avi', 'mpg', 'mpeg', 'mkv');
}

function fm_get_audio_exts() {
    return array('wav', 'mp3', 'ogg', 'm4a', 'flac', 'aac');
}

function fm_get_text_exts() {
    return array('txt', 'css', 'ini', 'conf', 'log', 'htaccess', 'passwd', 'sql', 'js', 'json', 'sh', 'config',
        'php', 'php4', 'php5', 'phps', 'phtml', 'htm', 'html', 'shtml', 'xhtml', 'xml', 'xsl', 'md', 'yml', 'yaml',
        'csv', 'twig', 'tpl', 'gitignore', 'less', 'sass', 'scss', 'c', 'cpp', 'cs', 'py', 'java', 'go', 'rs',
        'map', 'lock', 'dtd', 'svg', 'bat', 'ps1');
}

function fm_get_text_mimes() {
    return array('application/xml', 'application/javascript', 'application/x-javascript', 
                 'image/svg+xml', 'message/rfc822', 'application/json');
}

function fm_get_text_names() {
    return array('license', 'readme', 'authors', 'contributors', 'changelog', 'composer');
}

function fm_get_upload_accept() {
    if (empty(FM_UPLOAD_EXT)) return '';
    
    $exts = explode(',', FM_UPLOAD_EXT);
    $mimeMap = array(
        'jpg' => 'image/jpeg', 'jpeg' => 'image/jpeg', 'png' => 'image/png',
        'gif' => 'image/gif', 'webp' => 'image/webp', 'avif' => 'image/avif',
        'pdf' => 'application/pdf',
        'doc' => 'application/msword', 'docx' => 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'xls' => 'application/vnd.ms-excel', 'xlsx' => 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'zip' => 'application/zip',
        'txt' => 'text/plain', 'csv' => 'text/csv',
        'mp3' => 'audio/mpeg', 'mp4' => 'video/mp4',
    );
    
    $accept = array();
    foreach ($exts as $ext) {
        $ext = trim($ext);
        if (isset($mimeMap[$ext])) {
            $accept[] = $mimeMap[$ext];
        }
        $accept[] = '.' . $ext;
    }
    
    return implode(',', $accept);
}

class FM_Zipper {
    private $zip;

    public function __construct() {
        $this->zip = new ZipArchive();
    }

    public function create($filename, $files) {
        $res = $this->zip->open($filename, ZipArchive::CREATE | ZipArchive::OVERWRITE);
        if ($res !== true) {
            return false;
        }
        if (is_array($files)) {
            foreach ($files as $f) {
                if (!$this->addFileOrDir($f)) {
                    $this->zip->close();
                    return false;
                }
            }
            $this->zip->close();
            return true;
        } else {
            if ($this->addFileOrDir($files)) {
                $this->zip->close();
                return true;
            }
            return false;
        }
    }

    public function unzip($filename, $path) {
        $res = $this->zip->open($filename);
        if ($res !== true) {
            return false;
        }
        if ($this->zip->extractTo($path)) {
            $this->zip->close();
            return true;
        }
        return false;
    }

    private function addFileOrDir($filename) {
        if (is_file($filename)) {
            return $this->zip->addFile($filename, basename($filename));
        } elseif (is_dir($filename)) {
            return $this->addDir($filename);
        }
        return false;
    }

    private function addDir($path) {
        $base = basename($path);
        if (!$this->zip->addEmptyDir($base)) {
            return false;
        }
        $objects = scandir($path);
        if (is_array($objects)) {
            foreach ($objects as $file) {
                if ($file != '.' && $file != '..') {
                    if (is_dir($path . '/' . $file)) {
                        if (!$this->addDir($path . '/' . $file)) {
                            return false;
                        }
                    } elseif (is_file($path . '/' . $file)) {
                        if (!$this->zip->addFile($path . '/' . $file, $base . '/' . $file)) {
                            return false;
                        }
                    }
                }
            }
            return true;
        }
        return false;
    }
}

// --- 模板函数 ---

function fm_show_nav_path($path) {
    ?>
<div class="path">
<div class="float-right" style="display:flex;gap:12px;align-items:center">
<a href="?p=" title="Root directory" style="display:inline-flex;align-items:center;gap:4px;padding:4px 8px;border-radius:4px;background:#f3f4f6"><i class="icon-home"></i> Root</a>
<?php if (!FM_READONLY): ?>
<a href="?p=<?php echo urlencode(FM_PATH) ?>&amp;upload" title="Upload files" style="display:inline-flex;align-items:center;gap:4px;padding:4px 8px;border-radius:4px;background:#e0f2fe;color:#0369a1"><i class="icon-upload"></i> Upload</a>
<a href="#" onclick="newfolder('<?php echo fm_enc(FM_PATH) ?>');return false;" title="New folder" style="display:inline-flex;align-items:center;gap:4px;padding:4px 8px;border-radius:4px;background:#dcfce7;color:#166534"><i class="icon-folder_add"></i> New Folder</a>
<a href="#" onclick="newfile('<?php echo fm_enc(FM_PATH) ?>');return false;" title="New file" style="display:inline-flex;align-items:center;gap:4px;padding:4px 8px;border-radius:4px;background:#fef3c7;color:#92400e"><i class="icon-document"></i> New File</a>
<?php endif; ?>
<?php if (FM_USE_AUTH): ?>
<a href="?logout=1" title="Logout" style="display:inline-flex;align-items:center;gap:4px;padding:4px 8px;border-radius:4px;background:#fee2e2;color:#991b1b"><i class="icon-logout"></i> Logout</a>
<?php endif; ?>
</div>
        <?php
        $path = fm_clean_path($path);
        $root_url = "<a href='?p=' title='Root: " . fm_enc(FM_ROOT_PATH) . "' style='display:inline-flex;align-items:center'><i class='icon-home' style='margin-right:4px'></i> Root</a>";
        $sep = ' <span style="color:#9ca3af;margin:0 4px;">/</span> ';
        if ($path != '') {
            $exploded = explode('/', $path);
            $count = count($exploded);
            $array = array();
            $parent = '';
            for ($i = 0; $i < $count; $i++) {
                $parent = trim($parent . '/' . $exploded[$i], '/');
                $parent_enc = urlencode($parent);
                $array[] = "<a href='?p={$parent_enc}'>" . fm_enc(fm_convert_win($exploded[$i])) . "</a>";
            }
            $root_url .= $sep . implode($sep, $array);
        }
        echo '<div class="break-word" style="margin-top:8px;padding:8px;background:#f9fafb;border-radius:6px">' . $root_url . '</div>';
        ?>
</div>
<?php
}

function fm_show_message() {
    if (isset($_SESSION['message'])) {
        $class = $_SESSION['status'] ?? 'ok';
        echo '<p class="message ' . $class . '">' . $_SESSION['message'] . '</p>';
        unset($_SESSION['message'], $_SESSION['status']);
    }
}

function fm_show_header() {
    $sprites_ver = '20240101';
    header("Content-Type: text/html; charset=utf-8");
    header("Expires: Sat, 26 Jul 1997 05:00:00 GMT");
    header("Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0");
    header("Pragma: no-cache");
    
    // 安全头
    header("X-Frame-Options: SAMEORIGIN");
    header("X-Content-Type-Options: nosniff");
    header("X-XSS-Protection: 1; mode=block");
    header("Referrer-Policy: strict-origin-when-cross-origin");
    ?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PHP File Manager Secure</title>
<style>
html,body,div,span,p,pre,a,code,em,img,small,strong,ol,ul,li,form,label,table,tr,th,td{margin:0;padding:0;vertical-align:baseline;outline:none;font-size:100%;background:transparent;border:none;text-decoration:none}
html{overflow-y:scroll}body{padding:0;font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif;color:#333;background:#f5f5f5}
input,select,textarea,button{font-size:inherit;font-family:inherit}
a{color:#2563eb;text-decoration:none}a:hover{color:#dc2626;text-decoration:underline}
img{vertical-align:middle;border:none}span.gray{color:#6b7280}small{font-size:12px;color:#6b7280}p{margin-bottom:10px}
ul{margin-left:1.5em;margin-bottom:10px}ul li{padding:3px 0}
table{border-collapse:collapse;border-spacing:0;margin-bottom:15px;width:100%}
th,td{padding:8px 10px;text-align:left;vertical-align:top;border:1px solid #e5e7eb;background:#fff;white-space:nowrap}
th{background:#f9fafb;font-weight:600}td.gray{background:#f9fafb}
tr:hover td{background:#f3f4f6}tr:hover td.gray{background:#f9fafb}
code,pre{display:block;margin-bottom:10px;font:13px/1.5 'SF Mono',Monaco,'Cascadia Code','Roboto Mono',monospace;border:1px solid #e5e7eb;padding:10px;overflow:auto;background:#fafafa}
pre.with-hljs{padding:0}pre.with-hljs code{margin:0;border:0;overflow:visible}
code.maxheight,pre.maxheight{max-height:512px}
input[type="checkbox"]{margin:0;padding:0;accent-color:#2563eb}
input[type="text"],input[type="password"]{padding:8px 10px;border:1px solid #d1d5db;border-radius:6px;width:100%;max-width:300px}
input[type="submit"],button{padding:8px 16px;border:1px solid #d1d5db;border-radius:6px;background:#fff;cursor:pointer;font-weight:500}
input[type="submit"]:hover,button:hover{background:#f3f4f6}
#wrapper{max-width:1200px;margin:15px auto;padding:0 15px}
.path{padding:10px 15px;border:1px solid #e5e7eb;border-radius:8px;background:#fff;margin-bottom:15px}
.login-form{text-align:center;padding:30px}
.message{padding:10px 15px;border:1px solid #e5e7eb;border-radius:8px;background:#fff;margin-bottom:15px}
.message.ok{border-color:#10b981;color:#047857;background:#ecfdf5}
.message.error{border-color:#ef4444;color:#b91c1c;background:#fef2f2}
.message.alert{border-color:#f59e0b;color:#b45309;background:#fffbeb}
.btn{border:0;background:none;padding:0;margin:0;font-weight:500;color:#2563eb;cursor:pointer}.btn:hover{color:#dc2626}
.preview-img{max-width:100%;background:url("data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAIAAACQkWg2AAAAKklEQVR42mL5//8/Azbw+PFjrOJMDCSCUQ3EABZc4S0rKzsaSvTTABBgAMyfCMsY4B9iAAAAAElFTkSuQmCC") repeat}
.preview-video{position:relative;max-width:100%;height:0;padding-bottom:56.25%;margin-bottom:10px}.preview-video video{position:absolute;width:100%;height:100%;left:0;top:0;background:#000}
[class*="icon-"]{display:inline-block;width:16px;height:16px;background:url("<?php echo FM_SELF_URL ?>?img=sprites&amp;t=<?php echo $sprites_ver ?>") no-repeat 0 0;vertical-align:middle}
.icon-document{background-position:-16px 0}.icon-folder{background-position:-32px 0}
.icon-folder_add{background-position:-48px 0}.icon-upload{background-position:-64px 0}
.icon-arrow_up{background-position:-80px 0}.icon-home{background-position:-96px 0}
.icon-separator{background-position:-112px 0}.icon-cross{background-position:-128px 0}
.icon-copy{background-position:-144px 0}.icon-apply{background-position:-160px 0}
.icon-cancel{background-position:-176px 0}.icon-rename{background-position:-192px 0}
.icon-checkbox{background-position:-208px 0}.icon-checkbox_invert{background-position:-224px 0}
.icon-checkbox_uncheck{background-position:-240px 0}.icon-download{background-position:-256px 0}
.icon-goback{background-position:-272px 0}.icon-folder_open{background-position:-288px 0}
.icon-file_application{background-position:0 -16px}.icon-file_code{background-position:-16px -16px}
.icon-file_csv{background-position:-32px -16px}.icon-file_excel{background-position:-48px -16px}
.icon-file_film{background-position:-64px -16px}.icon-file_flash{background-position:-80px -16px}
.icon-file_font{background-position:-96px -16px}.icon-file_html{background-position:-112px -16px}
.icon-file_illustrator{background-position:-128px -16px}.icon-file_image{background-position:-144px -16px}
.icon-file_music{background-position:-160px -16px}.icon-file_outlook{background-position:-176px -16px}
.icon-file_pdf{background-position:-192px -16px}.icon-file_photoshop{background-position:-208px -16px}
.icon-file_php{background-position:-224px -16px}.icon-file_playlist{background-position:-240px -16px}
.icon-file_powerpoint{background-position:-256px -16px}.icon-file_swf{background-position:-272px -16px}
.icon-file_terminal{background-position:-288px -16px}.icon-file_text{background-position:-304px -16px}
.icon-file_word{background-position:-320px -16px}.icon-file_zip{background-position:-336px -16px}
.icon-logout{background-position:-304px 0}.icon-chain{background-position:-320px 0}
.icon-link_folder{background-position:-352px -16px}.icon-link_file{background-position:-368px -16px}
.compact-table{border:0;width:auto}.compact-table td,.compact-table th{width:100px;border:0;text-align:center}.compact-table tr:hover td{background:#fff}
.filename{max-width:400px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.break-word{word-wrap:break-word;word-break:break-word}
.footer{text-align:center;margin-top:20px;padding:15px;color:#6b7280}
.upload-area{border:2px dashed #d1d5db;border-radius:8px;padding:30px;text-align:center;background:#fafafa;transition:all 0.3s;cursor:pointer;margin-bottom:20px}
.upload-area:hover{border-color:#2563eb;background:#eff6ff}
.upload-area.dragover{border-color:#2563eb;background:#dbeafe}
.upload-area input[type="file"]{display:none}
.upload-icon{font-size:48px;color:#9ca3af;margin-bottom:10px}
.upload-text{font-size:16px;color:#6b7280;margin-bottom:5px}
.upload-hint{font-size:13px;color:#9ca3af}
.upload-queue{margin-top:20px;max-height:400px;overflow-y:auto}
.upload-item{background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:12px;margin-bottom:10px}
.upload-item-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:8px}
.upload-item-name{font-weight:500;color:#374151;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:300px}
.upload-item-size{font-size:12px;color:#6b7280}
.upload-item-status{display:flex;align-items:center;gap:8px}
.upload-status-badge{font-size:12px;padding:2px 8px;border-radius:12px;background:#f3f4f6;color:#6b7280}
.upload-status-badge.success{background:#dcfce7;color:#166534}
.upload-status-badge.error{background:#fee2e2;color:#991b1b}
.upload-status-badge.uploading{background:#dbeafe;color:#1e40af}
.upload-progress{height:6px;background:#e5e7eb;border-radius:3px;overflow:hidden;margin:8px 0}
.upload-progress-bar{height:100%;background:linear-gradient(90deg,#2563eb,#3b82f6);border-radius:3px;transition:width 0.3s;width:0%}
.upload-progress-bar.error{background:#ef4444}
.upload-progress-bar.success{background:#10b981}
.upload-item-actions{display:flex;gap:8px;margin-top:8px}
.upload-btn{font-size:12px;padding:4px 10px;border-radius:4px;border:1px solid #d1d5db;background:#fff;cursor:pointer;transition:all 0.2s}
.upload-btn:hover{background:#f3f4f6}
.upload-btn.retry{color:#2563eb;border-color:#2563eb}
.upload-btn.cancel{color:#dc2626;border-color:#dc2626}
.upload-error-message{font-size:12px;color:#dc2626;margin-top:4px;padding:4px 8px;background:#fef2f2;border-radius:4px}
.upload-actions{display:flex;justify-content:space-between;align-items:center;margin-top:20px;padding-top:15px;border-top:1px solid #e5e7eb}
.upload-summary{font-size:14px;color:#6b7280}
.upload-buttons{display:flex;gap:10px}
.upload-btn-primary{padding:8px 20px;background:#2563eb;color:#fff;border:none;border-radius:6px;cursor:pointer;font-weight:500}
.upload-btn-primary:hover{background:#1d4ed8}
.upload-btn-primary:disabled{background:#9ca3af;cursor:not-allowed}
.upload-btn-secondary{padding:8px 20px;background:#fff;color:#6b7280;border:1px solid #d1d5db;border-radius:6px;cursor:pointer}
.upload-btn-secondary:hover{background:#f3f4f6}
.upload-toast{position:fixed;bottom:20px;right:20px;padding:12px 20px;background:#1f2937;color:#fff;border-radius:8px;box-shadow:0 4px 12px rgba(0,0,0,0.15);z-index:9999;animation:slideIn 0.3s;max-width:350px}
.upload-toast.error{background:#dc2626}
.upload-toast.success{background:#10b981}
@keyframes slideIn{from{transform:translateX(100%);opacity:0}to{transform:translateX(0);opacity:1}}
</style>
<link rel="icon" href="<?php echo FM_SELF_URL ?>?img=favicon" type="image/png">
<?php if (isset($_GET['view']) && FM_USE_HIGHLIGHTJS): ?>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/<?php echo FM_HIGHLIGHTJS_STYLE ?>.min.css">
<?php endif; ?>
</head>
<body>
<div id="wrapper">
<?php
}

function fm_show_footer() {
    ?>
<div class="footer">
    <small>PHP File Manager Secure v<?php echo VERSION; ?></small>
</div>
</div>
<script>
function newfolder(p){
    var n = prompt('New folder name:', 'folder');
    if(n !== null && n !== '' && n.length <= 255){
        window.location.search = 'p=' + encodeURIComponent(p) + '&new=' + encodeURIComponent(n) + '&csrf_token=<?php echo urlencode(get_csrf_token()); ?>';
    }
}
function newfile(p){
    var n = prompt('New file name:', 'file.txt');
    if(n !== null && n !== '' && n.length <= 255){
        window.location.search = 'p=' + encodeURIComponent(p) + '&newfile=' + encodeURIComponent(n) + '&csrf_token=<?php echo urlencode(get_csrf_token()); ?>';
    }
}
function rename(p, f){
    var n = prompt('New name:', f);
    if(n !== null && n !== '' && n != f && n.length <= 255){
        window.location.search = 'p=' + encodeURIComponent(p) + '&ren=' + encodeURIComponent(f) + '&to=' + encodeURIComponent(n) + '&csrf_token=<?php echo urlencode(get_csrf_token()); ?>';
    }
}
function change_checkboxes(l, v){
    for(var i = l.length - 1; i >= 0; i--){
        l[i].checked = (typeof v === 'boolean') ? v : !l[i].checked;
    }
}
function get_checkboxes(){
    var i = document.getElementsByName('file[]'), a = [];
    for(var j = i.length - 1; j >= 0; j--){
        if(i[j].type == 'checkbox') a.push(i[j]);
    }
    return a;
}
function select_all(){ change_checkboxes(get_checkboxes(), true); }
function unselect_all(){ change_checkboxes(get_checkboxes(), false); }
function invert_all(){ change_checkboxes(get_checkboxes()); }
function checkbox_toggle(){
    var l = get_checkboxes();
    var selectAll = document.querySelector('th input[type="checkbox"]');
    var allChecked = l.every(function(cb){ return cb.checked; });
    change_checkboxes(l, !allChecked);
    if(selectAll) selectAll.checked = !allChecked;
}
document.addEventListener('keydown', function(e) {
    if (e.key === 'h' || e.key === 'H') {
        if (!['INPUT', 'TEXTAREA', 'SELECT'].includes(e.target.tagName)) {
            window.location.href = '?p=';
        }
    }
    if (e.key === 'u' || e.key === 'U') {
        if (!['INPUT', 'TEXTAREA', 'SELECT'].includes(e.target.tagName) && <?php echo FM_READONLY ? 'false' : 'true' ?>) {
            window.location.href = '?p=<?php echo urlencode(FM_PATH) ?>&upload';
        }
    }
});
</script>
<?php if (isset($_GET['view']) && FM_USE_HIGHLIGHTJS): ?>
<script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
<script>hljs.highlightAll();</script>
<?php endif; ?>
</body>
</html>
<?php
}

function fm_show_image($img) {
    $modified_time = gmdate('D, d M Y 00:00:00') . ' GMT';
    $expires_time = gmdate('D, d M Y 00:00:00', strtotime('+1 day')) . ' GMT';

    $img = trim($img);
    $images = fm_get_images();
    $image = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAEElEQVR42mL4//8/A0CAAQAI/AL+26JNFgAAAABJRU5ErkJggg==';
    if (isset($images[$img])) {
        $image = $images[$img];
    }
    $image = base64_decode($image);
    $size = strlen($image);

    header_remove('Cache-Control');
    header_remove('Pragma');
    header('Last-Modified: ' . $modified_time, true, 200);
    header('Expires: ' . $expires_time);
    header('Content-Length: ' . $size);
    header('Content-Type: image/png');
    echo $image;
    exit;
}

function fm_get_images() {
    return array(
        'favicon' => 'iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJ
bWFnZVJlYWR5ccllPAAAAZVJREFUeNqkk79Lw0AUx1+uidTQim4Waxfpnl1BcHMR6uLkIF0cpYOI
f4KbOFcRwbGTc0HQSVQQXCqlFIXgFkhIyvWS870LaaPYH9CDy8vdfb+fey930aSUMEvT6VHVzw8x
rKUX3N3Hj/8M+cZ6GcOtBPl6KY5iAA7KJzfVWrfbhUKhALZtQ6myDf1+X5nsuzjLUmUOnpa+v5r1
Z4ZDDfsLiwER45xDEATgOI6KntfDd091GidzC8vZ4vH1QQ09+4MSMAMWRREKPMhmsyr6voYmrnb2
PKEizdEabUaeFCDKCCHAdV0wTVNFznMgpVqGlZ2cipzHGtKSZwCIZJgJwxB38KHT6Sjx21V75Jcn
LXmGAKTRpGVZUx2dAqQzSEqw9kqwuGqONTufPrw37D8lQFxCvjgPXIixANLEGfwuQacMOC4kZz+q
GdhJS550BjpRCdCbAJCMJRkMASEIg+4Bxz4JwAwDSEueAYDLIM+QrOk6GHiRxjXSkJY8KUCvdXZ6
kbuvNx+mOcbN9taGBlpLAWf9nX8EGADoCfqkKWV/cgAAAABJRU5ErkJggg==',
        'sprites' => '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
RK5CYII=',
    );
}