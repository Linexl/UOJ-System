<?php
require_once $_SERVER['DOCUMENT_ROOT'].'/app/vendor/webauthn/WebAuthn.php';
	if (Auth::check()) {
		redirectTo('/');
	}

	function handleLoginPost() {
        $return = new stdClass();
		if (!crsf_check()) {
            $return->msg = 'expired';
			return json_encode($return);
		}
		if (!isset($_POST['username'])) {
            $return->msg = 'failed';
            return json_encode($return);
		}
		if (!isset($_POST['password'])) {
            $return->msg = 'failed';
            return json_encode($return);
		}
		$username = $_POST['username'];
		$password = $_POST['password'];
		
		if (!validateUsername($username)) {
            $return->msg = 'failed';
            return json_encode($return);
		}
		if (!validatePassword($password)) {
            $return->msg = 'failed';
            return json_encode($return);
		}
		
		$user = queryUser($username);
		if (!$user || !checkPassword($user, $password)) {
            $return->msg = 'failed';
            return json_encode($return);
		}
		
		if ($user['usergroup'] == 'B') {
            $return->msg = 'banned';
            return json_encode($return);
		}

        $result = DB::selectFirst("select * from user_2fa where username ='$username'");
        if($result['totp']=='close'&&$result['webauthn']=='close'){
            Auth::login($user['username']);
            $return->msg = 'ok';
            return json_encode($return);
        }else{
            $return->msg = '2fa';
            $return->totp = $result['totp'];
            $return->webauthn = $result['webauthn'];
            $return->rec = $result['rec'];
            return json_encode($return);
        }
	}

	function handle2FAPost() {
        $username = $_POST['username'];
        $password = $_POST['password'];
        $user = queryUser($username);
        if (!$user || !checkPassword($user, $password) || $user['usergroup'] == 'B') {
            return "Illegal Request";
        }
        $vtype = $_POST['vtype'];
        if ($vtype == 'totp'){
            $return = new stdClass();
            $vcode = $_POST['vcode'];
            $result = DB::selectFirst("select * from user_2fa where username ='$username'");
            if(strlen($vcode)==6) {
                if($result['totp'] == 'close'){
                    $return->success = false;
                    return json_encode($return);
                }
                $totpdata = queryTotp($username);
                if ($totpdata) {
                    $secret = $totpdata['secret'];
                    $timestamp = floor(microtime(true) / 30);
                    $binary_key = base32_decode($secret);
                    $binary_timestamp = pack('N*', 0) . pack('N*', $timestamp);
                    $hash = hash_hmac('sha1', $binary_timestamp, $binary_key, true);

                    $offset = ord($hash[19]) & 0xf;
                    $OTP = (
                            ((ord($hash[$offset + 0]) & 0x7f) << 24) |
                            ((ord($hash[$offset + 1]) & 0xff) << 16) |
                            ((ord($hash[$offset + 2]) & 0xff) << 8) |
                            (ord($hash[$offset + 3]) & 0xff)
                        ) % pow(10, 6);

                    if ($OTP == $_POST['vcode']) {
                        Auth::login($user['username']);
                        $return->success = true;
                        return json_encode($return);
                    }
                }
            }elseif(strlen($vcode)==16){
                $ok = false;
                if($result['rec1'] && $vcode == $result['rec1']){
                    DB::update("update user_2fa set rec1 = NULL where username = '$username'");
                    $ok=true;
                }elseif($result['rec2'] && $vcode == $result['rec2']){
                    DB::update("update user_2fa set rec2 = NULL where username = '$username'");
                    $ok=true;
                }elseif($result['rec3'] && $vcode == $result['rec3']){
                    DB::update("update user_2fa set rec3 = NULL where username = '$username'");
                    $ok=true;
                }elseif($result['rec4'] && $vcode == $result['rec4']){
                    DB::update("update user_2fa set rec4 = NULL where username = '$username'");
                    $ok=true;
                }
                if($ok){
                    Auth::login($user['username']);
                    $return->success = true;
                    return json_encode($return);
                }
            }
            $return->success = false;
            return json_encode($return);
        }elseif ($vtype == 'webauthn'){
            try {
                // read get argument and post body
                $type = $_POST['type'];
                $userVerification = 'required';
                $post = $_POST['response'];
                if ($post) {
                    $post = json_decode($post);
                }

                // Init
                // Supported Formats
                $formats = array('android-key','android-safetynet','apple','fido-u2f','none','packed','tpm');

                //current domain
                $rpId = $_POST['rpid'];
                if(!$rpId){
                    throw new Exception('invalid relying party ID');
                }

                // types selected on front end
                $typeUsb = true;
                $typeNfc = true;
                $typeBle = true;
                $typeInt = true;

                // cross-platform: true, if type internal is not allowed
                //                 false, if only internal is allowed
                //                 null, if internal and cross-platform is allowed
                $crossPlatformAttachment = null;

                // new Instance of the server library.
                // make sure that $rpId is the domain name.
                $WebAuthn = new lbuchs\WebAuthn\WebAuthn('UOJ', $rpId, $formats);

                // add root certificates to validate new registrations
                $WebAuthn->addRootCertificates($_SERVER['DOCUMENT_ROOT'].'/app/vendor/webauthn/rootCertificates/solo.pem');
                $WebAuthn->addRootCertificates($_SERVER['DOCUMENT_ROOT'].'/app/vendor/webauthn/rootCertificates/apple.pem');
                $WebAuthn->addRootCertificates($_SERVER['DOCUMENT_ROOT'].'/app/vendor/webauthn/rootCertificates/yubico.pem');
                $WebAuthn->addRootCertificates($_SERVER['DOCUMENT_ROOT'].'/app/vendor/webauthn/rootCertificates/hypersecu.pem');
                $WebAuthn->addRootCertificates($_SERVER['DOCUMENT_ROOT'].'/app/vendor/webauthn/rootCertificates/globalSign.pem');
                $WebAuthn->addRootCertificates($_SERVER['DOCUMENT_ROOT'].'/app/vendor/webauthn/rootCertificates/googleHardware.pem');
                $WebAuthn->addRootCertificates($_SERVER['DOCUMENT_ROOT'].'/app/vendor/webauthn/rootCertificates/microsoftTpmCollection.pem');

                // ------------------------------------
                // request for create arguments
                // ------------------------------------

                if ($type === 'getGetArgs') {
                    $ids = array();

                    // load registrations from session stored there by processCreate.
                    // normaly you have to load the credential Id's for a username
                    // from the database.
                    $data = queryCredentialId($username);
                    foreach ($data as $reg){
                        $ids[] = $reg['credentialId'];
                    }
                    if (count($ids) === 0) {
                        throw new Exception('registrations not found!');
                    }

                    $getArgs = $WebAuthn->getGetArgs($ids, 20, $typeUsb, $typeNfc, $typeBle, $typeInt, $userVerification);

                    // save challange to session. you have to deliver it to processGet later.
                    $_SESSION['webauthn-challenge'] = $WebAuthn->getChallenge();

                    return json_encode($getArgs);

                    // ------------------------------------
                    // process create
                    // ------------------------------------
                }  else if ($type === 'processGet') {
                    $clientDataJSON = base64_decode($post->clientDataJSON);
                    $authenticatorData = base64_decode($post->authenticatorData);
                    $signature = base64_decode($post->signature);
                    $id = base64_decode($post->id);
                    $challenge = $_SESSION['webauthn-challenge'];
                    $credentialPublicKey = null;

                    // looking up correspondending public key of the credential id
                    // you should also validate that only ids of the given user name
                    // are taken for the login.
                    $data = queryCredentialId($username);
                    if (isset($data)) {
                        foreach ($data as $reg) {
                            if ($reg['credentialId'] === $id) {
                                $credentialPublicKey = $reg['credentialPublicKey'];
                                break;
                            }
                        }
                    }

                    if ($credentialPublicKey === null) {
                        //it means Public Key for credential ID not found!
                        throw new Exception('Illegal Request');
                    }

                    // process the get request. throws WebAuthnException if it fails
                    $WebAuthn->processGet($clientDataJSON, $authenticatorData, $signature, $credentialPublicKey, $challenge, null, $userVerification === 'required');

                    Auth::login($user['username']);
                    unset($_SESSION['webauthn-challenge']);
                    $return = new stdClass();
                    $return->success = true;
                    return json_encode($return);

                }

            } catch (Throwable $ex) {
                $return = new stdClass();
                $return->success = false;
                $return->msg = $ex->getMessage();
                return json_encode($return);
            }
        }
        return 'Illegal Request';
    }

    function queryCredentialId($username)
    {
        $result = DB::selectAll("SELECT * FROM user_webauthn WHERE username = '$username'");
        $data = array();
        foreach ($result as $row){
            $data[] = array(
                "username" => $row["username"],
                "credentialId" => hex2bin($row["credentialId"]),
                "credentialPublicKey" => base64_decode($row["credentialPublicKey"]),
                "attestationFormat" => $row["attestationFormat"]
            );
        }
        return $data;
    }

	if (isset($_POST['login'])) {
		echo handleLoginPost();
		die();
	}
    if (isset($_POST['vtype'])) {
        echo handle2FAPost();
        die();
    }
?>
<?php
	$REQUIRE_LIB['md5'] = '';
?>
<?php echoUOJPageHeader(UOJLocale::get('login')) ?>
<h2 class="page-header"><?= UOJLocale::get('login') ?></h2>
<form id="form-login" class="form-horizontal" method="post">
  <div id="div-username" class="form-group">
    <label for="input-username" class="col-sm-2 control-label"><?= UOJLocale::get('username') ?></label>
    <div class="col-sm-3">
      <input type="text" class="form-control" id="input-username" name="username" placeholder="<?= UOJLocale::get('enter your username') ?>" maxlength="20" />
      <span class="help-block" id="help-username"></span>
    </div>
  </div>
  <div id="div-password" class="form-group">
    <label for="input-password" class="col-sm-2 control-label"><?= UOJLocale::get('password') ?></label>
    <div class="col-sm-3">
      <input type="password" class="form-control" id="input-password" name="password" placeholder="<?= UOJLocale::get('enter your password') ?>" maxlength="20" />
      <span class="help-block" id="help-password"></span>
    </div>
  </div>
  <div id="div-totp" class="form-group" style="display: none">
      <label for="input-totp" class="col-sm-2 control-label">验证码</label>
      <div class="col-sm-3">
          <input type="text" class="form-control" id="input-totp" name="totp" placeholder="输入6位TOTP验证码或恢复码" maxlength="16" />
          <span class="help-block" id="help-totp"></span>
      </div>
  </div>
    <div class="form-group">
    <div class="col-sm-offset-2 col-sm-3">
      <button type="submit" id="button-submit" class="btn btn-secondary"><?= UOJLocale::get('submit') ?></button>
    </div>
  </div>
</form>

<script type="text/javascript">
    function validateLoginPost() {
        var ok = true;
        ok &= getFormErrorAndShowHelp('username', validateUsername);
        ok &= getFormErrorAndShowHelp('password', validatePassword);
        return ok;
    }

    function submitLoginPost() {
        if (!validateLoginPost()) {
            return false;
        }
        clearAlerts();
        if($('#div-totp').is(':visible')){
            var totp = $('#input-totp').val();
            if(totp.length != 6 && totp.length != 16){
                $('#help-totp').html('验证码长度为6位！');
            }else submit_totp();
            return true;
        }

        $.post('/login', {
            _token : "<?= crsf_token() ?>",
            login : '',
            username : $('#input-username').val(),
            password : md5($('#input-password').val(), "<?= getPasswordClientSalt() ?>")
        }, function(msg) {
            msg=JSON.parse(msg);
            if (msg.msg == 'ok') {
                reloadPrev();
            } else if(msg.msg == '2fa'){
                if(msg.webauthn == 'open'){
                    checkregistration();
                }
                if(msg.rec == 'open'){
                    $('#div-totp').show();
                    $('#input-totp').focus();
                }
            } else if (msg.msg == 'banned') {
                $('#div-username').addClass('has-error');
                $('#help-username').html('该用户已被封停，请联系管理员。');
            } else if (msg.msg == 'expired') {
                $('#div-username').addClass('has-error');
                $('#help-username').html('页面会话已过期。');
            } else {
                $('#div-username').addClass('has-error');
                $('#help-username').html('用户名或密码错误。');
                $('#div-password').addClass('has-error');
                $('#help-password').html('用户名或密码错误。<a href="/forgot-password">忘记密码？</a>');
            }
        });
        return true;
    }

    function submit_totp() {
        clearAlerts();
        $.post('/login', {
            _token : "<?= crsf_token() ?>",
            vtype : 'totp',
            vcode : $('#input-totp').val(),
            username : $('#input-username').val(),
            password : md5($('#input-password').val(), "<?= getPasswordClientSalt() ?>")
        }, function(msg) {
            msg=JSON.parse(msg);
            if(msg.success == true){
                addAlerts('认证成功','alert-success');
                reloadPrev();
            } else {
                addAlerts('验证码错误，请重试。','alert-danger');
                $('#input-totp').val('');
            }
        })
            .fail(function () {
                addAlerts('网络错误！','alert-danger');
            });
    }

    function reloadPrev() {
        var prevUrl = document.referrer;
        if (prevUrl == '' || /.*\/login.*/.test(prevUrl) || /.*\/logout.*/.test(prevUrl) || /.*\/register.*/.test(prevUrl) || /.*\/reset-password.*/.test(prevUrl)) {
            prevUrl = '/';
        };
        window.location.href = prevUrl;
    }

    function addAlerts(text,type) {
        let alert = '<div class="alert '+type+' alert-dismissable" role="alert">'+text+
            '<button type="button" class="close" data-dismiss="alert" aria-hidden="true">&times;</button></div>';
        $('#form-login').prepend(alert);
    }

    function clearAlerts() {
        $('.alert').alert('close');
    }

    $(document).ready(function() {
        $('#form-login').submit(function(e) {
            e.preventDefault();
            submitLoginPost();
        });
    });

    //以下为Webauthn所使用的函数
    /**
     * checks a FIDO2 registration
     * @returns {undefined}
     */
    function checkregistration() {
        clearAlerts();

        if (!window.fetch || !navigator.credentials || !navigator.credentials.create) {
            console.log('当前浏览器不支持Webauthn，或站点未开启https传输!','alert-danger');
            return;
        }

        // get default args
        let formdata = new FormData();
        formdata.append("_token","<?= crsf_token() ?>");
        formdata.append("vtype","webauthn");
        formdata.append("type","getGetArgs");
        formdata.append("rpid",location.hostname);
        formdata.append("username",$('#input-username').val());
        formdata.append("password",md5($('#input-password').val(), "<?= getPasswordClientSalt() ?>"));
        window.fetch('/login', {method:'POST', body:formdata,cache:'no-cache'}).then(function(response) {
            return response.json();

            // convert base64 to arraybuffer
        }).then(function(json) {

            // error handling
            if (json.success === false) {
                throw new Error(json.msg);
            }

            // replace binary base64 data with ArrayBuffer. a other way to do this
            // is the reviver function of JSON.parse()
            recursiveBase64StrToArrayBuffer(json);
            return json;

            // create credentials
        }).then(function(getCredentialArgs) {
            // console.log(getCredentialArgs);
            return navigator.credentials.get(getCredentialArgs);

            // convert to base64
        }).then(function(cred) {
            return {
                id: cred.rawId ? arrayBufferToBase64(cred.rawId) : null,
                clientDataJSON: cred.response.clientDataJSON  ? arrayBufferToBase64(cred.response.clientDataJSON) : null,
                authenticatorData: cred.response.authenticatorData ? arrayBufferToBase64(cred.response.authenticatorData) : null,
                signature : cred.response.signature ? arrayBufferToBase64(cred.response.signature) : null
            };

            // transfer to server
        }).then(JSON.stringify).then(function(AuthenticatorAttestationResponse) {
            formdata = new FormData();
            formdata.append("_token","<?= crsf_token() ?>");
            formdata.append("vtype","webauthn");
            formdata.append("type","processGet");
            formdata.append("rpid",location.hostname);
            formdata.append("response",AuthenticatorAttestationResponse);
            formdata.append("username",$('#input-username').val());
            formdata.append("password",md5($('#input-password').val(), "<?= getPasswordClientSalt() ?>"));
            return window.fetch('/login', {method:'POST', body:formdata,cache:'no-cache'});

            // convert to json
        }).then(function(response) {
            return response.json();

            // analyze response
        }).then(function(json) {
            if (json.success) {
                reloadPrev();
                addAlerts(json.msg || '认证成功','alert-success');
            } else {
                throw new Error(json.msg);
            }

            // catch errors
        }).catch(function(err) {
            if(err.name == 'NotAllowedError'){
                addAlerts('用户取消认证或操作超时','alert-danger');
            }
            else if(err.name == 'NetworkError' || err.name == 'TypeError'){
                addAlerts('网络错误！','alert-danger');
            }else if(err.name == 'SyntaxError'){
                addAlerts('服务器内部错误！','alert-danger');
            }
            else addAlerts(err,'alert-danger');
        });
    }

    /**
     * convert RFC 1342-like base64 strings to array buffer
     * @param {mixed} obj
     * @returns {undefined}
     */
    function recursiveBase64StrToArrayBuffer(obj) {
        let prefix = '=?BINARY?B?';
        let suffix = '?=';
        if (typeof obj === 'object') {
            for (let key in obj) {
                if (typeof obj[key] === 'string') {
                    let str = obj[key];
                    if (str.substring(0, prefix.length) === prefix && str.substring(str.length - suffix.length) === suffix) {
                        str = str.substring(prefix.length, str.length - suffix.length);

                        let binary_string = window.atob(str);
                        let len = binary_string.length;
                        let bytes = new Uint8Array(len);
                        for (let i = 0; i < len; i++)        {
                            bytes[i] = binary_string.charCodeAt(i);
                        }
                        obj[key] = bytes.buffer;
                    }
                } else {
                    recursiveBase64StrToArrayBuffer(obj[key]);
                }
            }
        }
    }

    /**
     * Convert a ArrayBuffer to Base64
     * @param {ArrayBuffer} buffer
     * @returns {String}
     */
    function arrayBufferToBase64(buffer) {
        let binary = '';
        let bytes = new Uint8Array(buffer);
        let len = bytes.byteLength;
        for (let i = 0; i < len; i++) {
            binary += String.fromCharCode( bytes[ i ] );
        }
        return window.btoa(binary);
    }
    //以上为Webauthn使用的函数

</script>
<?php echoUOJPageFooter() ?>

