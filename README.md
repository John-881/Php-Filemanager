# PHP File Manager - 安全增强版

一个基于 PHP 的单文件在线文件管理器，经过安全增强和界面优化，适配 PHP 8.3。

## 📋 功能特点

- 🔐 **安全增强**
  - CSRF 令牌保护所有写操作
  - 路径遍历防护（使用 `realpath()` 验证）
  - 文件扩展名白名单验证
  - 安全的密码哈希（支持 `password_hash`）
  - IP 白名单/黑名单支持
  - 会话安全（登录后重新生成 Session ID）
  - 安全 HTTP 响应头

- 📁 **文件管理**
  - 浏览目录、查看文件
  - 创建、重命名、删除文件和文件夹
  - 复制、移动文件和文件夹
  - 批量操作（删除、复制、打包）
  - 文件上传（支持多文件、大文件分块上传）
  - 文件下载

- 👁️ **文件预览**
  - 图片预览（支持缩放）
  - 音频/视频播放
  - 文本文件语法高亮（Highlight.js）
  - 代码文件高亮（PHP、HTML、CSS、JS 等）
  - ZIP 压缩包内容预览
  - Office 文档在线预览（Google/Microsoft Viewer）

- 🎨 **界面优化**
  - 现代化响应式设计
  - 深色/浅色主题支持
  - 面包屑导航（带斜杠分隔）
  - 彩色图标按钮
  - 悬停效果
  - 快捷键支持

- 👥 **用户管理**
  - 多用户支持
  - 只读用户
  - 用户目录隔离
  - 全局只读模式

## 📦 安装部署

### 快速开始

1. 下载 `filemanager.php` 文件
2. 上传到服务器网站目录
3. 访问 `https://yourdomain.com/filemanager.php`

### 首次配置

打开文件，修改以下配置：

```php
// 认证开关
$use_auth = true;

// 用户凭证 - 请立即修改默认密码！
// 使用 password_hash('your_password', PASSWORD_DEFAULT) 生成
$auth_users = array(
    'admin' => '$2y$10$YourNewHashHere',
);

// 只读用户
$readonly_users = array('guest');

// 根路径（限制访问范围）
$root_path = $_SERVER['DOCUMENT_ROOT'] . '/uploads';

// 允许上传的文件扩展名
$allowed_upload_extensions = 'jpg,jpeg,png,gif,pdf,doc,docx,xls,xlsx,txt,zip';

// 最大上传大小（字节）- 100MB
$max_upload_size_bytes = 104857600;

// IP 白名单
$ip_whitelist = array('127.0.0.1', '::1', '你的IP');
$ip_ruleset = 'AND';  // OFF / AND / OR
```

### 生成密码哈希

访问 `https://yourdomain.com/filemanager.php?p=&help=2` 或使用 PHP 命令：

```php
php -r "echo password_hash('your_password', PASSWORD_DEFAULT);"
```

## 🔧 高级配置

### 用户目录隔离

```php
$directories_users = array(
    'user1' => '/home/user1/files',
    'user2' => '/home/user2/docs',
);
```

### 外部配置文件

创建 `filemanager_config.php` 覆盖默认配置：

```php
<?php
$use_auth = true;
$auth_users = array('admin' => '$2y$10$...');
$root_path = '/var/www/mydata';
$show_hidden_files = true;
```

### 隐藏文件显示

```php
$show_hidden_files = true;  // 显示 . 开头的文件
```

### 在线文档查看器

```php
$online_viewer = 'google';  // 'google', 'microsoft' 或 false
```

## 🛡️ 安全建议

1. **立即修改默认密码**
2. **限制根路径**：将 `$root_path` 设置为特定目录
3. **限制上传扩展名**：只允许必要的文件类型
4. **启用 IP 白名单**：`$ip_ruleset = 'AND'`
5. **使用 HTTPS**：保护传输安全
6. **定期更新 PHP**：使用 PHP 8.0+
7. **设置适当权限**：
   ```bash
   chmod 640 filemanager.php
   chown www-data:www-data filemanager.php
   ```

8. **Nginx 额外防护**：
   ```nginx
   location ~ /filemanager\.php {
       # 限制请求方法
       limit_except GET POST { deny all; }
       
       # 限制上传大小
       client_max_body_size 100M;
   }
   ```

9. **Apache .htaccess 防护**：
   ```apache
   <Files "filemanager.php">
       Order Allow,Deny
       Allow from all
   </Files>
   
   <Files "filemanager_config.php">
       Order Allow,Deny
       Deny from all
   </Files>
   ```

## ⌨️ 快捷键

| 快捷键 | 功能 |
|--------|------|
| `H` | 返回根目录 |
| `U` | 打开上传页面 |
| `N` | 新建文件夹 |

## 📱 界面预览

### 文件列表
- 面包屑导航显示当前路径（斜杠分隔）
- 彩色操作按钮（上传、新建、删除等）
- 文件/文件夹图标区分
- 权限和所有者信息（Linux）

### 文件预览
- 图片：支持缩放查看
- 音视频：HTML5 播放器
- 代码：语法高亮显示
- 文档：在线预览

## 🔄 更新日志

### v2.0-secure (2024)
- ✨ 全面安全增强
- ✨ PHP 8.3 兼容
- ✨ CSRF 保护
- ✨ 路径遍历修复
- ✨ 界面现代化改造
- ✨ 添加根目录快捷按钮
- ✨ 优化面包屑导航（斜杠分隔）
- ✨ 彩色图标按钮
- 🐛 修复多个已知漏洞

## ⚠️ 免责声明

本工具仅供授权管理员使用。请勿在未经授权的情况下部署于生产环境。使用者需自行承担安全责任。

## 📄 许可证

基于 [alexantr/filemanager](https://github.com/alexantr/filemanager) 修改

MIT License

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

## 📧 联系方式

如有问题或建议，请提交 GitHub Issue。
