# PHP File Manager - 安全增强版

一个功能强大且安全的 PHP 文件管理器，基于 [alexantr/filemanager](https://github.com/alexantr/filemanager) 进行了全面的安全增强和功能改进。

## ✨ 特性

- 🔐 **多层安全防护** - CSRF 保护、会话劫持防护、登录暴力破解防护
- 📁 **完整文件操作** - 上传、下载、复制、移动、删除、重命名、权限修改
- 📦 **压缩/解压支持** - 支持 ZIP 格式的打包和解包
- 👁️ **在线预览** - 支持图片、音视频、文本、代码高亮、Office/PDF（通过 Google/Microsoft 在线查看器）
- 🚀 **分块上传** - 支持大文件分块上传，带进度显示和断点续传
- 📱 **响应式界面** - 现代化的 UI 设计，支持移动端适配
- 🔐 **用户认证** - 多用户支持，可配置只读用户和目录限制
- 🌍 **IP 访问控制** - 支持 IP 白名单/黑名单

## 📋 系统要求

- PHP 7.4+ （推荐 PHP 8.3）
- ZipArchive 扩展（用于压缩/解压功能）
- Fileinfo 扩展（用于 MIME 类型检测）
- MBString 扩展（用于多字节字符处理）
- 可写的文件系统权限

## 🚀 快速开始

### 1. 下载安装

```bash
# 克隆仓库
git clone https://github.com/yourusername/php-filemanager-secure.git

# 或直接下载
wget https://example.com/filemanager_fixed.php
```

### 2. 配置密码

首先需要生成密码哈希：

```bash
php -r "echo password_hash('your_strong_password', PASSWORD_DEFAULT);"
```

然后将生成的哈希值填入 `$auth_users` 数组：

```php
$auth_users = array(
    'admin' => '$2y$10$YourGeneratedHashHere...',
);
```

### 3. 基础配置

编辑文件开头的配置部分：

```php
// 根路径 - 强烈建议限制为特定目录
$root_path = '/var/www/uploads';  // 不要使用 $_SERVER['DOCUMENT_ROOT']

// 允许上传的文件类型
$allowed_upload_extensions = 'jpg,jpeg,png,gif,pdf,doc,docx,xls,xlsx,txt,zip';

// 最大上传大小（字节）- 100MB
$max_upload_size_bytes = 104857600;

// 时区设置
$default_timezone = 'Asia/Shanghai';
```

### 4. 部署

将 `filemanager_fixed.php` 上传到您的服务器，通过浏览器访问即可。

> ⚠️ **安全提示**：建议将文件管理器放在需要认证的独立目录中，不要暴露在网站根目录。

## ⚙️ 配置选项

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `$use_auth` | `true` | 是否启用登录认证 |
| `$auth_users` | `array()` | 用户名 => 密码哈希的映射 |
| `$readonly_users` | `array()` | 只读用户列表 |
| `$global_readonly` | `false` | 全局只读模式 |
| `$directories_users` | `array()` | 用户目录限制 |
| `$root_path` | `$_SERVER['DOCUMENT_ROOT']` | 根目录路径 |
| `$allowed_upload_extensions` | `'jpg,jpeg,png,gif,pdf,doc,docx,xls,xlsx,txt,zip'` | 允许上传的文件扩展名 |
| `$max_upload_size_bytes` | `104857600` | 最大上传大小（100MB） |
| `$show_hidden_files` | `true` | 是否显示隐藏文件 |
| `$ip_ruleset` | `'OFF'` | IP 规则（'OFF', 'AND', 'OR'） |
| `$ip_whitelist` | `array('127.0.0.1', '::1')` | IP 白名单 |
| `$ip_blacklist` | `array()` | IP 黑名单 |
| `$online_viewer` | `'google'` | 在线文档查看器（'google', 'microsoft', false） |
| `$csrf_protection` | `true` | CSRF 保护开关 |

## 🔒 安全特性

### 认证与授权
- 密码使用 `password_hash()` 加密存储
- 登录失败限制（5次/15分钟锁定）
- 会话劫持防护（验证 User-Agent 和 IP）
- 会话固定攻击防护（登录后重新生成会话 ID）

### 文件操作安全
- 路径遍历防护（`realpath` 验证）
- 文件扩展名白名单验证
- 上传文件 MIME 类型检测
- 敏感文件名过滤（如 `.htaccess`）
- 大文件分块下载防止内存溢出

### Web 安全
- CSRF Token 保护所有状态变更操作
- 安全响应头（X-Frame-Options, X-Content-Type-Options 等）
- Cookie 安全标志（HttpOnly, SameSite=Strict, Secure）
- 输出 HTML 编码防止 XSS

## 📖 使用说明

### 快捷键

| 快捷键 | 功能 |
|--------|------|
| `H` | 返回根目录 |
| `U` | 打开上传页面 |
| `N` | 新建文件夹 |

### 批量操作

1. 勾选需要操作的文件/文件夹
2. 点击底部的操作按钮：
   - **删除选中** - 删除所有选中项
   - **打包为ZIP** - 将选中项打包为 ZIP 压缩包
   - **复制选中** - 批量复制到其他目录

### 文件预览

- **图片**：直接显示预览，支持懒加载
- **音视频**：使用 HTML5 播放器
- **文本/代码**：支持语法高亮（需开启 Highlight.js）
- **Office/PDF**：通过 Google Docs 或 Microsoft Office 在线查看

## 🌐 外部配置文件

您可以创建 `filemanager_config.php` 来覆盖默认配置：

```php
<?php
// filemanager_config.php
$use_auth = true;
$auth_users = array(
    'admin' => '$2y$10$...',
    'user' => '$2y$10$...',
);
$readonly_users = array('user');
$root_path = '/var/www/user_uploads';
$allowed_upload_extensions = 'jpg,jpeg,png,gif,pdf,zip';
$default_timezone = 'Asia/Shanghai';
```

## 🛠️ 故障排除

### 上传失败

1. 检查 `upload_max_filesize` 和 `post_max_size` PHP 配置
2. 确认目标目录有写入权限
3. 检查 `$allowed_upload_extensions` 配置

### 无法登录

1. 确认密码哈希生成正确
2. 检查会话目录是否有写入权限
3. 清除浏览器 Cookie 后重试

### 路径错误

1. 确认 `$root_path` 目录存在且可读
2. 检查 PHP `open_basedir` 限制

## ⚠️ 安全建议

1. **立即修改默认密码** - 不要使用空密码或弱密码
2. **限制根路径** - 将 `$root_path` 设置为特定目录，而非网站根目录
3. **使用 HTTPS** - 始终通过 HTTPS 访问，保护登录凭证
4. **定期更新** - 关注安全更新，及时升级
5. **限制访问 IP** - 使用 IP 白名单功能限制访问来源
6. **文件类型限制** - 只开放必要的文件扩展名上传

## 📄 许可证

本项目基于 MIT 许可证开源。原始项目 [alexantr/filemanager](https://github.com/alexantr/filemanager) 采用 MIT 许可证。

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

## 📝 更新日志

### v2.0-secure-final

- 全面的安全审计和修复
- 添加登录失败限制和会话劫持防护
- 增强文件上传安全验证
- 改进 CSRF 保护机制
- 优化大文件处理和内存使用
- 添加安全响应头
- 修复多个 XSS 和路径遍历漏洞
