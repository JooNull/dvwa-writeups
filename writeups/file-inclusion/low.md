# File Inclusion — Low Security

## Overview

- **Application:** Damn Vulnerable Web Application (DVWA)
- **Vulnerability:** File Inclusion
- **Security Level:** Low
- **Entry Point:** `GET` parameter `page`
- **Source Files:**
  - `vulnerabilities/fi/index.php`
  - `vulnerabilities/fi/source/low.php`

## Description

File Inclusion occurs when an application dynamically includes a file based on user-controlled input without properly validating or restricting the requested path.

In DVWA's Low security level, the application assigns the `page` parameter to a variable and passes it directly to PHP's `include()` function.

This allows an attacker to include unintended local files and may expose sensitive information. Depending on the application and PHP configuration, File Inclusion can sometimes lead to code execution.

## Source Code Analysis

### `low.php`

```php
<?php

// The page we wish to display
$file = $_GET['page'];

?>
```

The application retrieves the `page` parameter from the URL and stores it in `$file`.

For example:

```text
?vulnerabilities/fi/index.php?page=file1.php
```

The variable becomes:

```php
$file = "file1.php";
```

This assignment alone does not include the file. The inclusion occurs later in `index.php`.

### `index.php`

```php
require_once DVWA_WEB_PAGE_TO_ROOT . "vulnerabilities/fi/source/{$vulnerabilityFile}";

if (isset($file))
    include($file);
else {
    header('Location:?page=include.php');
    exit;
}
```

The application selects the security-level-specific source file and then passes `$file` directly to `include()`.

Because the value originates from user input and is not restricted to an approved set of files, an attacker can provide paths outside the intended application directory.

## Root Cause

The vulnerability is caused by:

- Directly using user-controlled input in `include()`.
- Missing validation and allowlisting of permitted files.
- Missing restrictions that confine file access to the intended directory.

The application trusts the supplied path instead of mapping user input to predefined, permitted files.

## Exploitation

### 1. Absolute Path

An absolute path specifies a file's location directly from the filesystem root.

Example:

```text
?page=/etc/os-release
```

**Observed result:** The contents of `/etc/os-release` were successfully displayed.

This confirms that the application can include a local file outside the intended application directory.

### 2. Relative Path / Path Traversal

Relative paths can use directory traversal sequences (`../`) to navigate outside the current directory.

Example:

```text
?page=../../../../../etc/os-release
```

The number of traversal sequences required depends on the application's working directory and path resolution.

**Observed result:** Relative-path traversal successfully accessed a file outside the intended application directory.

### 3. PHP Filter — Source Code Disclosure

PHP stream filters can transform file contents before they are returned through a stream. The `convert.base64-encode` filter can encode a file's contents as Base64.

Example:

```text
?page=php://filter/convert.base64-encode/resource=/var/www/html/vulnerabilities/fi/source/low.php
```

The Base64 output can be decoded locally:

```bash
printf '%s' 'BASE64_OUTPUT' | base64 -d
```

**Observed result:** The source code of `low.php` was retrieved and decoded successfully.

This technique can expose application logic without displaying the original PHP source directly. The resource path must match the actual filesystem location.

### 4. Existing Application Files

DVWA provides three example files:

```text
file1.php
file2.php
file3.php
```

These can be selected through the `page` parameter.

Example:

```text
?page=file1.php
```

Testing existing files and a nonexistent filename helps determine how the application handles valid and invalid inclusion targets.

### 5. Error Handling

A nonexistent file can be requested to observe the application's behavior.

Example:

```text
?page=missing.php
```

Depending on PHP configuration, the application may display a warning, return an incomplete page, or log an error.

Error messages may disclose filesystem paths and other implementation details.

### 6. Remote File Inclusion (RFI)

RFI occurs when an application includes a resource from a remote URL.

RFI testing has been deferred and has not yet been confirmed in this lab.

The setting `allow_url_include` being enabled does not, by itself, prove that RFI is exploitable. Remote access, wrapper support, application behavior, and PHP configuration must also permit the operation.

### 7. Remote Code Execution (RCE)

File Inclusion can sometimes lead to code execution, but arbitrary file reading does not automatically imply RCE.

Potential outcomes depend on the included resource, its contents, the inclusion context, and the server's configuration.

RCE has not been confirmed in this lab.

## Impact

Depending on the files accessible and the server configuration, File Inclusion may result in:

- **Sensitive Information Disclosure:** Reading local configuration files or other accessible files.
- **Source Code Disclosure:** Exposing application code and potentially hardcoded secrets.
- **Application Logic Disclosure:** Understanding internal implementation details.
- **Remote File Inclusion:** Potentially including remote resources if the required conditions are met.
- **Remote Code Execution:** Possible in specific circumstances, but not established by the current tests.

The demonstrated impact in this lab is arbitrary local file access and PHP source code disclosure.

## Mitigation

- **Use an Allowlist:** Map user-facing identifiers to predefined files instead of accepting arbitrary paths.
- **Avoid Direct User-Controlled Inclusion:** Never pass raw request parameters directly to `include()` or `require()`.
- **Restrict File Access:** Resolve paths and ensure they remain within an approved directory.
- **Disable Remote Inclusion When Unnecessary:** Keep `allow_url_include` disabled in production environments.
- **Apply Least Privilege:** Run the application with only the filesystem permissions it needs.
- **Handle Errors Safely:** Avoid exposing internal paths or detailed PHP warnings to users.
- **Keep PHP and Dependencies Updated:** Use supported versions and secure configuration defaults.
