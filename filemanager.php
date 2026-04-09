<?php
/**
 * PHP File Manager - Security Enhanced Version
 * Original: https://github.com/alexantr/filemanager
 * Enhanced for PHP 8.3 with security improvements
 */

// --- 安全配置 ---
// 认证开关
$use_auth = true;

// 用户凭证 - 请立即修改默认密码！
// 密码哈希生成: password_hash('your_password', PASSWORD_DEFAULT)
$auth_users = array(
    'admin' => '', // 请使用 password_hash() 生成新密码
);

// 只读用户列表
$readonly_users = array();

// 全局只读模式
$global_readonly = false;

// 用户目录限制 (用户名 => 目录路径)
$directories_users = array();

// 启用 highlight.js
$use_highlightjs = true;

// highlight.js 样式
$highlightjs_style = 'vs';

// 默认时区
$default_timezone = 'UTC';

// 根路径 - 限制访问范围
$root_path = $_SERVER['DOCUMENT_ROOT'];

// 根URL
$root_url = '';

// 服务器主机名
$http_host = $_SERVER['HTTP_HOST'];

// 输入编码
$iconv_input_encoding = 'UTF-8';

// 日期格式
$datetime_format = 'Y-m-d H:i:s';

// 允许的文件扩展名 (创建/重命名) - 留空允许所有
$allowed_file_extensions = '';

// 允许上传的文件扩展名 - 强烈建议限制！
$allowed_upload_extensions = 'jpg,jpeg,png,gif,pdf,doc,docx,xls,xlsx,txt,zip';

// 显示隐藏文件 (以点开头的文件)
$show_hidden_files = true;

// 隐藏权限/所有者列
$hide_Cols = false;

// 排除项目 (不显示的文件/文件夹)
$exclude_items = array();

// 在线文档查看器 ('google', 'microsoft' 或 false)
$online_viewer = 'google';

// 最大上传大小 (字节) - 默认 100MB
$max_upload_size_bytes = 104857600;

// IP 规则 ('OFF', 'AND', 'OR')
$ip_ruleset = 'OFF';

// IP 白名单
$ip_whitelist = array('127.0.0.1', '::1');

// IP 黑名单
$ip_blacklist = array();

// 路径显示模式 ('full', 'relative', 'host')
$path_display_mode = 'full';

// CSRF 保护
$csrf_protection = true;

// 会话名称
define('FM_SESSION_ID', 'filemanager_secure');

// 版本
define('VERSION', '2.0-secure');

// --- 以下一般不需要修改 ---

$is_https = isset($_SERVER['HTTPS']) && (strtolower($_SERVER['HTTPS']) == 'on' || $_SERVER['HTTPS'] == 1)
    || isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] == 'https';

// 加载外部配置
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
    
    // 安全的会话启动
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
}

// 生成 CSRF Token
if ($csrf_protection && empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// 验证 CSRF Token
function verify_csrf_token($token) {
    global $csrf_protection;
    if (!$csrf_protection) return true;
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

// 获取 CSRF Token
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

// 清理根URL
$root_url = fm_clean_path($root_url);

// 定义常量
defined('FM_ROOT_PATH') || define('FM_ROOT_PATH', $root_path);
defined('FM_ROOT_URL') || define('FM_ROOT_URL', ($is_https ? 'https' : 'http') . '://' . $http_host . (!empty($root_url) ? '/' . $root_url : ''));
defined('FM_SELF_URL') || define('FM_SELF_URL', ($is_https ? 'https' : 'http') . '://' . $http_host . $_SERVER['PHP_SELF']);

// 登出
if (isset($_GET['logout'])) {
    $_SESSION = array();
    if (isset($_COOKIE[session_name()])) {
        setcookie(session_name(), '', time() - 42000, '/');
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

// 认证
if ($use_auth) {
    if (isset($_SESSION['logged'], $auth_users[$_SESSION['logged']])) {
        // 已登录
        
        // 更新用户目录
        if (isset($directories_users[$_SESSION['logged']])) {
            $root_path = $directories_users[$_SESSION['logged']];
            if (!@is_dir($root_path)) {
                $root_path = FM_ROOT_PATH;
            }
        }
        
        // 检查只读状态
        $is_readonly = $global_readonly || in_array($_SESSION['logged'], $readonly_users);
    } elseif (isset($_POST['fm_usr'], $_POST['fm_pwd'])) {
        // 登录处理
        sleep(1);
        
        if ($csrf_protection && !verify_csrf_token($_POST['csrf_token'] ?? '')) {
            fm_set_msg('Invalid security token', 'error');
            fm_redirect(FM_SELF_URL);
        }
        
        $username = $_POST['fm_usr'];
        $password = $_POST['fm_pwd'];
        
        if (isset($auth_users[$username])) {
            $stored_hash = $auth_users[$username];
            
            // 支持明文密码(向后兼容)和哈希密码
            if (password_get_info($stored_hash)['algo'] > 0) {
                $valid = password_verify($password, $stored_hash);
            } else {
                $valid = ($password === $stored_hash);
            }
            
            if ($valid) {
                session_regenerate_id(true);
                $_SESSION['logged'] = $username;
                fm_set_msg('You are logged in');
                fm_redirect(FM_SELF_URL . '?p=');
            } else {
                unset($_SESSION['logged']);
                fm_set_msg('Wrong password', 'error');
                fm_redirect(FM_SELF_URL);
            }
        } else {
            unset($_SESSION['logged']);
            fm_set_msg('Wrong username or password', 'error');
            fm_redirect(FM_SELF_URL);
        }
    } else {
        // 显示登录表单
        unset($_SESSION['logged']);
        fm_show_header();
        fm_show_message();
        ?>
        <div class="path">
            <div class="login-form">
                <h2 style="margin-bottom:20px">PHP File Manager</h2>
                <form action="" method="post" style="margin:10px;text-align:center">
                    <input type="text" name="fm_usr" value="" placeholder="Username" required autocomplete="username" style="padding:8px;margin:5px;width:200px"><br>
                    <input type="password" name="fm_pwd" value="" placeholder="Password" required autocomplete="current-password" style="padding:8px;margin:5px;width:200px"><br>
                    <input type="hidden" name="csrf_token" value="<?php echo fm_enc(get_csrf_token()); ?>">
                    <input type="submit" value="Login" style="padding:8px 30px;margin:10px;cursor:pointer">
                </form>
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

// 检查只读权限
function check_write_permission() {
    if (FM_READONLY) {
        fm_set_msg('Write operations are disabled', 'error');
        fm_redirect(FM_SELF_URL . '?p=' . urlencode(FM_PATH));
    }
}

// 验证文件扩展名
function is_allowed_extension($filename, $type = 'file') {
    $allowed = ($type == 'upload') ? FM_UPLOAD_EXT : FM_FILE_EXT;
    if (empty($allowed)) return true;
    
    $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    if (empty($ext)) return true;
    
    $allowed_arr = explode(',', $allowed);
    return in_array($ext, $allowed_arr);
}

// 检查文件是否在排除列表中
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
    
    if (!verify_csrf_token($_POST['csrf_token'] ?? $_GET['csrf_token'] ?? '')) {
        fm_set_msg('Invalid security token', 'error');
        fm_redirect(FM_SELF_URL . '?p=' . urlencode(FM_PATH));
    }
    
    $new = strip_tags($_GET['new']);
    $new = fm_clean_path($new);
    $new = str_replace('/', '', $new);
    
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
    
    if (!verify_csrf_token($_POST['csrf_token'] ?? $_GET['csrf_token'] ?? '')) {
        fm_set_msg('Invalid security token', 'error');
        fm_redirect(FM_SELF_URL . '?p=' . urlencode(FM_PATH));
    }
    
    $new = strip_tags($_GET['newfile']);
    $new = fm_clean_path($new);
    $new = str_replace('/', '', $new);
    
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
    
    if (!verify_csrf_token($_POST['csrf_token'] ?? $_GET['csrf_token'] ?? '')) {
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
    
    if (!verify_csrf_token($_POST['csrf_token'] ?? $_GET['csrf_token'] ?? '')) {
        fm_set_msg('Invalid security token', 'error');
        fm_redirect(FM_SELF_URL . '?p=' . urlencode(FM_PATH));
    }
    
    $old = fm_clean_path($_GET['ren']);
    $old = str_replace('/', '', $old);
    $new = fm_clean_path($_GET['to']);
    $new = str_replace('/', '', $new);
    
    $path = FM_ROOT_PATH;
    if (FM_PATH != '') {
        $path .= '/' . FM_PATH;
    }
    
    // 检查是否是文件且需要验证扩展名
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
        // 安全的文件下载
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_write_close();
        }
        
        $filename = basename($real_file);
        $mime_type = fm_get_mime_type($real_file);
        
        header('Content-Description: File Transfer');
        header('Content-Type: ' . $mime_type);
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        header('Content-Transfer-Encoding: binary');
        header('Expires: 0');
        header('Cache-Control: must-revalidate, post-check=0, pre-check=0');
        header('Pragma: public');
        header('Content-Length: ' . filesize($real_file));
        
        readfile($real_file);
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
        fm_set_msg('Invalid security token', 'error');
        fm_redirect(FM_SELF_URL . '?p=' . urlencode(FM_PATH));
    }
    
    $path = FM_ROOT_PATH;
    if (FM_PATH != '') {
        $path .= '/' . FM_PATH;
    }

    $errors = 0;
    $uploads = 0;
    $total = count($_FILES['upload']['name'] ?? []);
    
    $allowed_ext = FM_UPLOAD_EXT ? explode(',', FM_UPLOAD_EXT) : [];

    for ($i = 0; $i < $total; $i++) {
        $tmp_name = $_FILES['upload']['tmp_name'][$i] ?? '';
        $filename = $_FILES['upload']['name'][$i] ?? '';
        $error = $_FILES['upload']['error'][$i] ?? UPLOAD_ERR_NO_FILE;
        
        if ($error === UPLOAD_ERR_OK && !empty($tmp_name) && $tmp_name != 'none') {
            // 检查文件大小
            if ($_FILES['upload']['size'][$i] > $max_upload_size_bytes) {
                $errors++;
                continue;
            }
            
            // 检查扩展名
            $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
            if (!empty($allowed_ext) && $ext != '' && !in_array($ext, $allowed_ext)) {
                $errors++;
                continue;
            }
            
            // 清理文件名
            $filename = fm_sanitize_filename($filename);
            
            if (move_uploaded_file($tmp_name, $path . '/' . $filename)) {
                $uploads++;
            } else {
                $errors++;
            }
        } elseif ($error !== UPLOAD_ERR_NO_FILE) {
            $errors++;
        }
    }

    if ($errors == 0 && $uploads > 0) {
        fm_set_msg(sprintf('All files uploaded to <b>%s</b>', fm_enc($path)));
    } elseif ($errors == 0 && $uploads == 0) {
        fm_set_msg('Nothing uploaded', 'alert');
    } else {
        fm_set_msg(sprintf('Error while uploading files. Uploaded files: %s', $uploads), 'error');
    }

    fm_redirect(FM_SELF_URL . '?p=' . urlencode(FM_PATH));
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
    
    if (!verify_csrf_token($_POST['csrf_token'] ?? $_GET['csrf_token'] ?? '')) {
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

// 修改权限 (非 Windows)
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

// 获取当前路径
$path = FM_ROOT_PATH;
if (FM_PATH != '') {
    $path .= '/' . FM_PATH;
}

// 检查路径
if (!is_dir($path)) {
    fm_redirect(FM_SELF_URL . '?p=');
}

// 获取父目录
$parent = fm_get_parent_path(FM_PATH);

$objects = is_readable($path) ? scandir($path) : array();
$folders = array();
$files = array();

if (is_array($objects)) {
    foreach ($objects as $file) {
        if ($file == '.' || $file == '..') {
            continue;
        }
        
        // 隐藏文件过滤
        if (!FM_SHOW_HIDDEN && substr($file, 0, 1) === '.') {
            continue;
        }
        
        $new_path = $path . '/' . $file;
        
        // 排除项目过滤
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
    ?>
    <div class="path">
        <p><b>Uploading files</b></p>
        <p class="break-word">Destination folder: <?php echo fm_enc(fm_convert_win(FM_ROOT_PATH . '/' . FM_PATH)) ?></p>
        <p class="break-word">Maximum file size: <?php echo $max_upload_mb ?> MB</p>
        <p class="break-word">Allowed extensions: <?php echo FM_UPLOAD_EXT ?: 'All' ?></p>
        <form action="" method="post" enctype="multipart/form-data">
            <input type="hidden" name="p" value="<?php echo fm_enc(FM_PATH) ?>">
            <input type="hidden" name="upl" value="1">
            <input type="hidden" name="csrf_token" value="<?php echo fm_enc(get_csrf_token()); ?>">
            <div id="upload-fields">
                <input type="file" name="upload[]" style="margin:5px"><br>
                <input type="file" name="upload[]" style="margin:5px"><br>
                <input type="file" name="upload[]" style="margin:5px"><br>
                <input type="file" name="upload[]" style="margin:5px"><br>
                <input type="file" name="upload[]" style="margin:5px"><br>
            </div>
            <button type="button" onclick="addUploadField()" style="margin:5px;padding:5px 10px">+ Add more</button>
            <br>
            <p>
                <button class="btn" style="padding:8px 20px"><i class="icon-apply"></i> Upload</button> &nbsp;
                <b><a href="?p=<?php echo urlencode(FM_PATH) ?>"><i class="icon-cancel"></i> Cancel</a></b>
            </p>
        </form>
    </div>
    <script>
    function addUploadField() {
        var div = document.getElementById('upload-fields');
        var input = document.createElement('input');
        input.type = 'file';
        input.name = 'upload[]';
        input.style.margin = '5px';
        div.appendChild(input);
        div.appendChild(document.createElement('br'));
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
        $content = file_get_contents($real_file);
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
                    echo 'Image sizes: ' . $image_size[0] . ' x ' . $image_size[1] . '<br>';
                }
            }
            if ($is_text) {
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
            <b><a href="<?php echo fm_enc($file_url) ?>" target="_blank"><i class="icon-chain"></i> Open</a></b> &nbsp;
            <?php if (!FM_READONLY): ?>
                <b><a href="?p=<?php echo urlencode(FM_PATH) ?>&amp;del=<?php echo urlencode($file) ?>" onclick="return confirm('Delete this file?');"><i class="icon-cross"></i> Delete</a></b> &nbsp;
                <b><a href="#" onclick="rename('<?php echo fm_enc(FM_PATH) ?>', '<?php echo fm_enc($file) ?>');return false;"><i class="icon-rename"></i> Rename</a></b> &nbsp;
            <?php endif; ?>
            <?php
            if ($is_zip && $filenames !== false && !FM_READONLY) {
                $zip_name = pathinfo($real_file, PATHINFO_FILENAME);
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
                echo '<iframe src="https://docs.google.com/viewer?embedded=true&url=' . urlencode($file_url) . '" frameborder="0" style="width:100%;min-height:460px"></iframe>';
            } elseif ($online_viewer == 'microsoft') {
                echo '<iframe src="https://view.officeapps.live.com/op/embed.aspx?src=' . urlencode($file_url) . '" frameborder="0" style="width:100%;min-height:460px"></iframe>';
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
            echo '<p><img src="' . fm_enc($file_url) . '" alt="" class="preview-img"></p>';
        } elseif ($is_audio) {
            echo '<p><audio src="' . fm_enc($file_url) . '" controls preload="metadata"></audio></p>';
        } elseif ($is_video) {
            echo '<div class="preview-video"><video src="' . fm_enc($file_url) . '" width="640" height="360" controls preload="metadata"></video></div>';
        } elseif ($is_text) {
            if (FM_USE_HIGHLIGHTJS) {
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
// 父目录链接
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
<a title="删除文件夹" href="?p=<?php echo urlencode(FM_PATH) ?>&amp;del=<?php echo urlencode($f) ?>" onclick="return confirm('确定删除这个文件夹吗？');" style="display:inline-flex;align-items:center;gap:2px;margin-right:6px;color:#dc2626"><i class="icon-cross"></i></a>
<a title="重命名" href="#" onclick="rename('<?php echo fm_enc(FM_PATH) ?>', '<?php echo fm_enc($f) ?>');return false;" style="display:inline-flex;align-items:center;gap:2px;margin-right:6px;color:#2563eb"><i class="icon-rename"></i></a>
<a title="复制到..." href="?p=&amp;copy=<?php echo urlencode(trim(FM_PATH . '/' . $f, '/')) ?>" style="display:inline-flex;align-items:center;gap:2px;margin-right:6px;color:#059669"><i class="icon-copy"></i></a>
<?php endif; ?>
<a title="直接链接" href="<?php echo fm_enc(FM_ROOT_URL . (FM_PATH != '' ? '/' . FM_PATH : '') . '/' . $f . '/') ?>" target="_blank" style="display:inline-flex;align-items:center;gap:2px;color:#6b7280"><i class="icon-chain"></i></a>
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
<a title="删除文件" href="?p=<?php echo urlencode(FM_PATH) ?>&amp;del=<?php echo urlencode($f) ?>" onclick="return confirm('确定删除这个文件吗？');" style="display:inline-flex;align-items:center;gap:2px;margin-right:6px;color:#dc2626"><i class="icon-cross"></i></a>
<a title="重命名" href="#" onclick="rename('<?php echo fm_enc(FM_PATH) ?>', '<?php echo fm_enc($f) ?>');return false;" style="display:inline-flex;align-items:center;gap:2px;margin-right:6px;color:#2563eb"><i class="icon-rename"></i></a>
<a title="复制到..." href="?p=<?php echo urlencode(FM_PATH) ?>&amp;copy=<?php echo urlencode(trim(FM_PATH . '/' . $f, '/')) ?>" style="display:inline-flex;align-items:center;gap:2px;margin-right:6px;color:#059669"><i class="icon-copy"></i></a>
<?php endif; ?>
<a title="直接链接" href="<?php echo fm_enc(FM_ROOT_URL . (FM_PATH != '' ? '/' . FM_PATH : '') . '/' . $f) ?>" target="_blank" style="display:inline-flex;align-items:center;gap:2px;margin-right:6px;color:#6b7280"><i class="icon-chain"></i></a>
<form method="post" style="display:inline" action="?p=<?php echo urlencode(FM_PATH) ?>&amp;dl=<?php echo urlencode($f) ?>">
<input type="hidden" name="csrf_token" value="<?php echo fm_enc(get_csrf_token()); ?>">
<button type="submit" title="下载" style="display:inline-flex;align-items:center;gap:2px;padding:0;background:none;border:none;color:#2563eb;cursor:pointer"><i class="icon-download"></i></button>
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
Full size: <span title="<?php printf('%s bytes', $all_files_size) ?>"><?php echo fm_get_filesize($all_files_size) ?></span>,
files: <?php echo $num_files ?>,
folders: <?php echo $num_folders ?>
</td></tr>
<?php
}
?>
</table>

<p class="path" style="display:flex;flex-wrap:wrap;align-items:center;gap:8px">
<a href="?p=" title="回到根目录" style="display:inline-flex;align-items:center;gap:4px;padding:4px 10px;background:#f3f4f6;border-radius:4px"><i class="icon-home"></i>根目录</a>
<span style="color:#d1d5db">|</span>
<a href="#" onclick="select_all();return false;" style="display:inline-flex;align-items:center;gap:4px;padding:4px 10px"><i class="icon-checkbox"></i>全选</a>
<a href="#" onclick="unselect_all();return false;" style="display:inline-flex;align-items:center;gap:4px;padding:4px 10px"><i class="icon-checkbox_uncheck"></i>取消全选</a>
<a href="#" onclick="invert_all();return false;" style="display:inline-flex;align-items:center;gap:4px;padding:4px 10px"><i class="icon-checkbox_invert"></i>反选</a>
<?php if (!FM_READONLY): ?>
<span style="color:#d1d5db">|</span>
<a href="#" onclick="newfolder('<?php echo fm_enc(FM_PATH) ?>');return false;" style="display:inline-flex;align-items:center;gap:4px;padding:4px 10px;background:#dcfce7;color:#166534;border-radius:4px"><i class="icon-folder_add"></i>新建文件夹</a>
<a href="#" onclick="newfile('<?php echo fm_enc(FM_PATH) ?>');return false;" style="display:inline-flex;align-items:center;gap:4px;padding:4px 10px;background:#fef3c7;color:#92400e;border-radius:4px"><i class="icon-document"></i>新建文件</a>
<a href="?p=<?php echo urlencode(FM_PATH) ?>&amp;upload" style="display:inline-flex;align-items:center;gap:4px;padding:4px 10px;background:#e0f2fe;color:#0369a1;border-radius:4px"><i class="icon-upload"></i>上传文件</a>
<?php endif; ?>
</p>

<?php if (!FM_READONLY): ?>
<p style="display:flex;gap:8px;margin-top:10px">
<button type="submit" name="delete" onclick="return confirm('确认删除选中的文件和文件夹？')" style="display:inline-flex;align-items:center;gap:4px;padding:6px 16px;background:#fee2e2;color:#991b1b;border:1px solid #fecaca;border-radius:6px;cursor:pointer"><i class="icon-cross"></i>删除选中</button>
<button type="submit" name="zip" onclick="return confirm('确认创建压缩包？')" style="display:inline-flex;align-items:center;gap:4px;padding:6px 16px;background:#f3f4f6;border:1px solid #d1d5db;border-radius:6px;cursor:pointer"><i class="icon-file_zip"></i>打包为ZIP</button>
<button type="submit" name="copy" style="display:inline-flex;align-items:center;gap:4px;padding:6px 16px;background:#f3f4f6;border:1px solid #d1d5db;border-radius:6px;cursor:pointer"><i class="icon-copy"></i>复制选中</button>
</p>
<?php endif; ?>

</form>

<?php
fm_show_footer();

// --- 函数定义 ---

/**
 * 获取客户端 IP
 */
function getClientIP() {
    $headers = ['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_CLIENT_IP', 'REMOTE_ADDR'];
    foreach ($headers as $header) {
        if (!empty($_SERVER[$header])) {
            $ip = $_SERVER[$header];
            if (strpos($ip, ',') !== false) {
                $ips = explode(',', $ip);
                $ip = trim($ips[0]);
            }
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }
        }
    }
    return '0.0.0.0';
}

/**
 * 清理文件名
 */
function fm_sanitize_filename($filename) {
    $filename = preg_replace('/[^\p{L}\p{N}\s\._-]/u', '', $filename);
    $filename = preg_replace('/\.{2,}/', '.', $filename);
    $filename = trim($filename, " \t\n\r\0\x0B.");
    if (empty($filename)) {
        $filename = 'file_' . date('Ymd_His');
    }
    return $filename;
}

/**
 * 递归删除
 */
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

/**
 * 重命名
 */
function fm_rename($old, $new) {
    return (!file_exists($new) && file_exists($old)) ? rename($old, $new) : null;
}

/**
 * 递归复制
 */
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

/**
 * 创建目录
 */
function fm_mkdir($dir, $force) {
    if (file_exists($dir)) {
        if (is_dir($dir)) {
            return $dir;
        } elseif (!$force) {
            return false;
        }
        unlink($dir);
    }
    return mkdir($dir, 0777, true);
}

/**
 * 复制文件
 */
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

/**
 * 获取 MIME 类型
 */
function fm_get_mime_type($file_path) {
    if (function_exists('finfo_open')) {
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $mime = finfo_file($finfo, $file_path);
        finfo_close($finfo);
        return $mime;
    } elseif (function_exists('mime_content_type')) {
        return mime_content_type($file_path);
    }
    return 'application/octet-stream';
}

/**
 * 重定向
 */
function fm_redirect($url, $code = 302) {
    header('Location: ' . $url, true, $code);
    exit;
}

/**
 * 清理路径
 */
function fm_clean_path($path) {
    $path = trim($path);
    $path = trim($path, '\\/');
    $path = str_replace(array('../', '..\\', "\0", "\r", "\n"), '', $path);
    if ($path == '..') {
        $path = '';
    }
    return str_replace('\\', '/', $path);
}

/**
 * 获取父路径
 */
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

/**
 * 获取显示路径
 */
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

/**
 * 获取文件大小
 */
function fm_get_filesize($size) {
    $units = array('B', 'KB', 'MB', 'GB', 'TB');
    $power = $size > 0 ? floor(log($size, 1024)) : 0;
    $power = min($power, count($units) - 1);
    return sprintf('%s %s', round($size / pow(1024, $power), 2), $units[$power]);
}

/**
 * 获取 ZIP 信息
 */
function fm_get_zif_info($path) {
    if (function_exists('zip_open')) {
        $arch = @zip_open($path);
        if ($arch) {
            $filenames = array();
            while ($zip_entry = @zip_read($arch)) {
                $zip_name = @zip_entry_name($zip_entry);
                $filenames[] = array(
                    'name' => $zip_name,
                    'filesize' => @zip_entry_filesize($zip_entry),
                    'compressed_size' => @zip_entry_compressedsize($zip_entry),
                    'folder' => substr($zip_name, -1) == '/'
                );
            }
            @zip_close($arch);
            return $filenames;
        }
    }
    return false;
}

/**
 * HTML 编码
 */
function fm_enc($text) {
    return htmlspecialchars($text ?? '', ENT_QUOTES, 'UTF-8');
}

/**
 * 设置消息
 */
function fm_set_msg($msg, $status = 'ok') {
    $_SESSION['message'] = $msg;
    $_SESSION['status'] = $status;
}

/**
 * 检查 UTF-8
 */
function fm_is_utf8($string) {
    return preg_match('//u', $string);
}

/**
 * 转换 Windows 文件名
 */
function fm_convert_win($filename) {
    if (FM_IS_WIN && function_exists('iconv')) {
        $filename = iconv(FM_ICONV_INPUT_ENC, 'UTF-8//IGNORE', $filename);
    }
    return $filename;
}

/**
 * 获取文件图标
 */
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

/**
 * 图片扩展名
 */
function fm_get_image_exts() {
    return array('ico', 'gif', 'jpg', 'jpeg', 'jpc', 'jp2', 'jpx', 'xbm', 'wbmp', 'png', 'bmp', 'tif', 'tiff', 'webp', 'avif', 'svg');
}

/**
 * 视频扩展名
 */
function fm_get_video_exts() {
    return array('webm', 'mp4', 'm4v', 'ogm', 'ogv', 'mov', 'avi', 'mpg', 'mpeg', 'mkv');
}

/**
 * 音频扩展名
 */
function fm_get_audio_exts() {
    return array('wav', 'mp3', 'ogg', 'm4a', 'flac', 'aac');
}

/**
 * 文本扩展名
 */
function fm_get_text_exts() {
    return array('txt', 'css', 'ini', 'conf', 'log', 'htaccess', 'passwd', 'sql', 'js', 'json', 'sh', 'config',
        'php', 'php4', 'php5', 'phps', 'phtml', 'htm', 'html', 'shtml', 'xhtml', 'xml', 'xsl', 'md', 'yml', 'yaml',
        'csv', 'twig', 'tpl', 'gitignore', 'less', 'sass', 'scss', 'c', 'cpp', 'cs', 'py', 'java', 'go', 'rs',
        'map', 'lock', 'dtd', 'svg', 'bat', 'ps1');
}

/**
 * 文本 MIME 类型
 */
function fm_get_text_mimes() {
    return array('application/xml', 'application/javascript', 'application/x-javascript', 
                 'image/svg+xml', 'message/rfc822', 'application/json');
}

/**
 * 文本文件名
 */
function fm_get_text_names() {
    return array('license', 'readme', 'authors', 'contributors', 'changelog', 'composer');
}

/**
 * ZIP 操作类
 */
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

/**
 * 显示导航路径
 */
function fm_show_nav_path($path) {
    $csrf_token = get_csrf_token();
    ?>
<div class="path">
<div class="float-right" style="display:flex;gap:12px;align-items:center">
<a href="?p=" title="Root directory" style="display:inline-flex;align-items:center;gap:4px;padding:4px 8px;border-radius:4px;background:#f3f4f6"><i class="icon-home"></i>根目录</a>
<?php if (!FM_READONLY): ?>
<a href="?p=<?php echo urlencode(FM_PATH) ?>&amp;upload" title="Upload files" style="display:inline-flex;align-items:center;gap:4px;padding:4px 8px;border-radius:4px;background:#e0f2fe;color:#0369a1"><i class="icon-upload"></i>上传</a>
<a href="#" onclick="newfolder('<?php echo fm_enc(FM_PATH) ?>');return false;" title="New folder" style="display:inline-flex;align-items:center;gap:4px;padding:4px 8px;border-radius:4px;background:#dcfce7;color:#166534"><i class="icon-folder_add"></i>新建文件夹</a>
<a href="#" onclick="newfile('<?php echo fm_enc(FM_PATH) ?>');return false;" title="New file" style="display:inline-flex;align-items:center;gap:4px;padding:4px 8px;border-radius:4px;background:#fef3c7;color:#92400e"><i class="icon-document"></i>新建文件</a>
<?php endif; ?>
<?php if (FM_USE_AUTH): ?>
<a href="?logout=1" title="Logout" style="display:inline-flex;align-items:center;gap:4px;padding:4px 8px;border-radius:4px;background:#fee2e2;color:#991b1b"><i class="icon-logout"></i>退出</a>
<?php endif; ?>
</div>
        <?php
        $path = fm_clean_path($path);
        // 面包屑导航 - 带斜杠分隔符
        $root_url = "<a href='?p=' title='根目录: " . fm_enc(FM_ROOT_PATH) . "' style='display:inline-flex;align-items:center'><i class='icon-home' style='margin-right:4px'></i>根目录</a>";
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

/**
 * 显示消息
 */
function fm_show_message() {
    if (isset($_SESSION['message'])) {
        $class = $_SESSION['status'] ?? 'ok';
        echo '<p class="message ' . $class . '">' . $_SESSION['message'] . '</p>';
        unset($_SESSION['message'], $_SESSION['status']);
    }
}

/**
 * 显示页头
 */
function fm_show_header() {
    $sprites_ver = '20240101';
    header("Content-Type: text/html; charset=utf-8");
    header("Expires: Sat, 26 Jul 1997 05:00:00 GMT");
    header("Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0");
    header("Pragma: no-cache");
    
    // 安全头
    header("X-Frame-Options: SAMEORIGIN");
    header("X-Content-Type-Options: nosniff");
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

/* 图标样式 */
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

/* 表格样式 */
.compact-table{border:0;width:auto}.compact-table td,.compact-table th{width:100px;border:0;text-align:center}.compact-table tr:hover td{background:#fff}
.filename{max-width:400px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.break-word{word-wrap:break-word;word-break:break-word}

/* 页脚 */
.footer{text-align:center;margin-top:20px;padding:15px;color:#6b7280}

/* 操作按钮统一样式 */
.path a,
.path button,
.action-btn {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 4px 10px;
    margin: 0 2px;
    border-radius: 4px;
    transition: all 0.2s;
    color: #374151;
    text-decoration: none;
}

.path a:hover,
.action-btn:hover {
    background-color: #f3f4f6;
    filter: brightness(0.95);
    text-decoration: none;
}

.path a i,
.action-btn i {
    margin-right: 2px;
}

/* 面包屑导航链接样式 */
.break-word a {
    color: #2563eb;
    text-decoration: none;
}
.break-word a:hover {
    text-decoration: underline;
    background: none;
}

/* 提交按钮样式 */
input[type="submit"] {
    margin-right: 8px;
    padding: 6px 16px;
}

/* 带背景色的特殊按钮 */
.btn-home {
    background: #f3f4f6;
    color: #374151;
}
.btn-upload {
    background: #e0f2fe;
    color: #0369a1;
}
.btn-newfolder {
    background: #dcfce7;
    color: #166534;
}
.btn-newfile {
    background: #fef3c7;
    color: #92400e;
}
.btn-logout {
    background: #fee2e2;
    color: #991b1b;
}
.btn-delete {
    background: #fee2e2;
    color: #991b1b;
    border: 1px solid #fecaca;
}
.btn-zip, .btn-copy {
    background: #f3f4f6;
    border: 1px solid #d1d5db;
}

/* 文件列表操作按钮颜色 */
.file-action-delete { color: #dc2626; }
.file-action-rename { color: #2563eb; }
.file-action-copy { color: #059669; }
.file-action-link { color: #6b7280; }
.file-action-download { color: #2563eb; }
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

/**
 * 显示页脚
 */
function fm_show_footer() {
    ?>
<div class="footer">
    <small>PHP File Manager Secure v<?php echo VERSION; ?></small>
</div>
</div>
<script>
function newfolder(p){
    var n = prompt('New folder name:', 'folder');
    if(n !== null && n !== ''){
        window.location.search = 'p=' + encodeURIComponent(p) + '&new=' + encodeURIComponent(n) + '&csrf_token=<?php echo urlencode(get_csrf_token()); ?>';
    }
}
function newfile(p){
    var n = prompt('New file name:', 'file.txt');
    if(n !== null && n !== ''){
        window.location.search = 'p=' + encodeURIComponent(p) + '&newfile=' + encodeURIComponent(n) + '&csrf_token=<?php echo urlencode(get_csrf_token()); ?>';
    }
}
function rename(p, f){
    var n = prompt('New name:', f);
    if(n !== null && n !== '' && n != f){
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
// 键盘快捷键
document.addEventListener('keydown', function(e) {
    // 按 H 键回到根目录（不区分大小写，且不在输入框中）
    if ((e.key === 'h' || e.key === 'H') && 
        !['INPUT', 'TEXTAREA', 'SELECT'].includes(e.target.tagName)) {
        window.location.href = '?p=';
    }
    // 按 U 键打开上传页面
    if ((e.key === 'u' || e.key === 'U') && 
        !['INPUT', 'TEXTAREA', 'SELECT'].includes(e.target.tagName) &&
        <?php echo FM_READONLY ? 'false' : 'true' ?>) {
        window.location.href = '?p=<?php echo urlencode(FM_PATH) ?>&upload';
    }
    // 按 N 键新建文件夹
    if ((e.key === 'n' || e.key === 'N') && 
        !['INPUT', 'TEXTAREA', 'SELECT'].includes(e.target.tagName) &&
        <?php echo FM_READONLY ? 'false' : 'true' ?>) {
        newfolder('<?php echo fm_enc(FM_PATH) ?>');
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

/**
 * 显示图片
 */
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

/**
 * 获取图片资源
 */
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
