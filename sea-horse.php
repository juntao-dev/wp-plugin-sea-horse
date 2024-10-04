<?php
/*
 * Plugin Name: My TOTP
 */


 // Add a TOTP input field to the login form
 function add_totp_field_to_login() {
     ?>
     <p>
         <label for="totp">TOTP Token<br/>
         <input type="text" name="totp" id="totp" class="input" value="" size="20" /></label>
     </p>
     <?php
 }
 add_action('login_form', 'add_totp_field_to_login');
 
 // Function to validate TOTP token using a hardcoded secret
 function validate_totp_token($user, $username, $password) {
     // Hardcoded secret (use this same secret in your Google Authenticator app)
     $secret = 'JBSWY3DPEHPK3PXP'; // This is a dummy base32 encoded secret
 
     // Check if the TOTP field is present and not empty
     if (isset($_POST['totp']) && !empty($_POST['totp'])) {
         $totp = sanitize_text_field($_POST['totp']);
 
         // Validate the TOTP token using the hardcoded secret
         if (!verify_totp_token($secret, $totp)) {
             return new WP_Error('invalid_totp', __('<strong>ERROR</strong>: Invalid TOTP token.'));
         }
     } else {
         return new WP_Error('empty_totp', __('<strong>ERROR</strong>: Please enter your TOTP token.'));
     }
 
     return $user; // If everything is valid, return the user object
 }
 add_filter('authenticate', 'validate_totp_token', 30, 3);
 
 // Function to verify TOTP token based on the secret
 function verify_totp_token($secret, $totp) {
     // TOTP generation parameters
     $timeSlice = floor(time() / 30); // 30-second window for TOTP
 
     // Decode the base32 secret
     $decodedSecret = base32_decode($secret);
 
     // Generate a valid TOTP for the current and adjacent time slices
     for ($i = -1; $i <= 1; $i++) {
         $calculatedTotp = generate_totp($decodedSecret, $timeSlice + $i);
         if ($calculatedTotp == $totp) {
             return true;
         }
     }
     return false;
 }
 
 // Function to generate a TOTP token
 function generate_totp($secret, $timeSlice) {
     $time = pack('N*', 0) . pack('N*', $timeSlice);
     $hash = hash_hmac('sha1', $time, $secret, true);
     $offset = ord($hash[19]) & 0xf;
     $otp = (
         ((ord($hash[$offset + 0]) & 0x7f) << 24) |
         ((ord($hash[$offset + 1]) & 0xff) << 16) |
         ((ord($hash[$offset + 2]) & 0xff) << 8) |
         (ord($hash[$offset + 3]) & 0xff)
     ) % pow(10, 6);
     return str_pad($otp, 6, '0', STR_PAD_LEFT); // Return 6-digit token
 }
 
 // Function to decode Base32 secret
 function base32_decode($secret) {
     if (empty($secret)) return '';
     $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
     $paddingCharCount = substr_count($secret, '=');
     $allowedValues = [6, 4, 3, 1, 0];
     if (!in_array($paddingCharCount, $allowedValues)) return false;
     $secret = str_replace('=', '', $secret);
     $binaryString = '';
     for ($i = 0; $i < strlen($secret); $i++) {
         $currentChar = $secret[$i];
         $currentCharIndex = strpos($alphabet, $currentChar);
         if ($currentCharIndex === false) return false;
         $binaryString .= str_pad(decbin($currentCharIndex), 5, '0', STR_PAD_LEFT);
     }
     $eightBits = str_split($binaryString, 8);
     $decodedString = '';
     for ($i = 0; $i < count($eightBits); $i++) {
         $decodedString .= chr(bindec($eightBits[$i]));
     }
     return $decodedString;
 }
 
 // Function to add a message on the login page
 function add_custom_login_message() {
     $message = get_option('custom_login_message', '');
     if (!empty($message)) {
         echo '<p class="custom-login-message" style="color:red;">' . esc_html($message) . '</p>';
     }
 }
 add_action('login_message', 'add_custom_login_message');
 
 // Function to run on plugin activation
 function custom_login_message_activation() {
     $message = 'This is a custom login message!';
     update_option('custom_login_message', $message);
 }
 register_activation_hook(__FILE__, 'custom_login_message_activation');
 
 // Function to run on plugin deactivation
 function custom_login_message_deactivation() {
     delete_option('custom_login_message');
 }
 register_deactivation_hook(__FILE__, 'custom_login_message_deactivation');
 