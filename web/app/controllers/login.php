<?php
require_once $_SERVER['DOCUMENT_ROOT'].'/app/vendor/webauthn/WebAuthn.php';
if (Auth::check()) {
	redirectTo('/');
}

function handleLoginPost() {
	if (!crsf_check()) {
		return 'expired';
	}
	if (!isset($_POST['username'])) {
		return "failed";
	}
	if (!isset($_POST['password'])) {
		return "failed";
	}
	$username = $_POST['username'];
	$password = $_POST['password'];

	if (!validateUsername($username)) {
		return "failed";
	}
	if (!validatePassword($password)) {
		return "failed";
	}

	$user = queryUser($username);
	if (!$user || !checkPassword($user, $password)) {
		return "failed";
	}

	if ($user['usergroup'] == 'B') {
		return "banned";
	}

	//Auth::login($user['username']);
	return "ok";
}

function handle2FAPost() {
	if( handleLoginPost()!='ok' ) return "Illegal Request";
	$username = $_POST['username'];
	$user = queryUser($username);
	$vtype = $_POST['vtype'];
	if($vtype == 'mail'){
		if(isset($_SESSION['mailcode']) && $_SESSION['mailcode'] == $_POST['vcode']){
			Auth::login($user['username']);
			unset($_SESSION['mailcode']);
			return "ok";
		}else {
			return "failed";
		}
	}elseif ($vtype == 'sendmail'){
		return sendMailCode($user);
	}elseif ($vtype == 'totp'){
		$totpdata = queryTotp($username);
		if($totpdata){
			$secret = $totpdata['secret'];
			$timestamp = floor(microtime(true)/30);
			$binary_key = base32_decode($secret);
			$binary_timestamp = pack('N*', 0) . pack('N*', $timestamp);
			$hash = hash_hmac ('sha1', $binary_timestamp, $binary_key, true);

			$offset = ord($hash[19]) & 0xf;
			$OTP = (
					((ord($hash[$offset+0]) & 0x7f) << 24 ) |
					((ord($hash[$offset+1]) & 0xff) << 16 ) |
					((ord($hash[$offset+2]) & 0xff) << 8 ) |
					(ord($hash[$offset+3]) & 0xff)
				) % pow(10, 6);

			if($OTP == $_POST['vcode']){
				Auth::login($user['username']);
				return "ok";
			}
		}
		return "failed";
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
			$rpId = 'localhost';
//        if ($_GET['rpId']) {
//            $rpId = filter_input(INPUT_GET, 'rpId', FILTER_VALIDATE_DOMAIN);
//            if ($rpId === false) {
//                throw new Exception('invalid relying party ID');
//            }
//        }

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

				// ------------------------------------
				// proccess clear registrations
				// ------------------------------------

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

function sendMailCode($user) {
	$randvcode = uojRandVCode(6);
	$oj_name = UOJConfig::$data['profile']['oj-name'];
	$oj_name_short = UOJConfig::$data['profile']['oj-name-short'];
	$_SESSION['mailcode']=$randvcode;
	$html = <<<EOD
<base target="_blank" />

<p>{$user['username']}您好，</p>
<p>您申请的{$oj_name_short}登陆验证码为：</p>
<p><h1>{$randvcode}</h1></p>
<p>请不要将验证码泄露给他人。如非本人操作，请及时修改密码。</p>
<p>{$oj_name}</p>

<style type="text/css">
body{font-size:14px;font-family:arial,verdana,sans-serif;line-height:1.666;padding:0;margin:0;overflow:auto;white-space:normal;word-wrap:break-word;min-height:100px}
pre {white-space:pre-wrap;white-space:-moz-pre-wrap;white-space:pre-wrap;white-space:-o-pre-wrap;word-wrap:break-word}
h1  {align="center";letter-spacing:10px;margin-left:30px}
</style>
EOD;
	$mailer = UOJMail::noreply();
	$mailer->addAddress($user['email'], $user['username']);
	$mailer->Subject = $oj_name_short."登录验证码";
	$mailer->msgHTML($html);
	if (!$mailer->send()) {
		error_log($mailer->ErrorInfo);
		return 'failed';
	} else {
		return 'ok';
	}
}
function addCredentialId($username,$credentialId,$credentialPublicKey,$attestationFormat){
	$credentialId = bin2hex($credentialId);
	$credentialPublicKey = base64_encode($credentialPublicKey);
	if(DB::insert("INSERT INTO user_webauthn VALUES ('$username','$credentialId','$credentialPublicKey','$attestationFormat')") == FALSE){
		return 'database error';
	}
	return 'ok';
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
function get2faStatus(){
	$return = new stdClass();
	$return->mail = true;
	$return->totp = true;
	$return->webauthn = true;
	return json_encode($return);
}

if (isset($_POST['login'])) {
	echo handleLoginPost();
	die();
}
if (isset($_POST['vtype'])) {
	echo handle2FAPost();
	die();
}
if (isset($_POST['status'])) {
	echo get2faStatus();
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
	<div class="form-group">
		<div class="col-sm-offset-2 col-sm-3">
			<button type="submit" id="button-submit" class="btn btn-secondary"><?= UOJLocale::get('submit') ?></button>
		</div>
	</div>
</form>
<!-- 模态框 -->
<div class="modal fade" id="authModal" data-backdrop="static">
	<div class="modal-dialog modal-dialog-centered modal-dialog-scrollable">
		<div class="modal-content">
			<!-- 模态框头部 -->
			<div class="modal-header">
				<h4 class="modal-title">二次登录验证</h4>
				<!--                <button type="button" class="close" data-dismiss="modal">&times;</button>-->
			</div>
			<!-- 模态框主体 -->
			<div class="modal-body" style="height: 360px">
				<!-- Nav tabs -->
				<ul class="nav nav-tabs" role="tablist">
					<li class="nav-item"><a class="nav-link" data-toggle="tab" href="#mail">邮件</a></li>
					<li class="nav-item"><a class="nav-link" data-toggle="tab" href="#totp">TOTP</a></li>
					<li class="nav-item"><a class="nav-link" data-toggle="tab" href="#webauthn">WebAuthn</a></li>
				</ul><br>
				<!-- Tab panes -->
				<div class="tab-content">

					<div id="mail" class="container tab-pane fade">
						<form id="form-mail" class="form-horizontal">
							<div class="form-group col-8">
								<label for="input-mail">请输入您邮箱中收到的验证码：</label>
								<input type="text" maxlength="6" class="form-control" style="font-size: 18px;text-transform:uppercase" id="input-mail" placeholder="验证码" autocomplete="off"
									   onkeyup="value=value.replace(/[^\w\.\/]/ig,'')">
							</div>
							<div class="form-group col-8">
								<button type="button" class="btn btn-secondary" id="submitmail">提交</button>
								<button type="button" class="btn btn-primary" id="sendcode">发送验证码</button>
							</div>
						</form>
					</div>

					<div id="totp" class="container tab-pane fade">
						<form id="form-totp" class="form-horizontal">
							<div class="form-group col-8">
								<label for="input-totp">已使用验证器应用保护您的登录信息，请在下面输入您的验证码：</label>
								<input type="text" minlength="6" maxlength="8" class="form-control" style="font-size: 18px;text-transform:uppercase" id="input-totp" placeholder="验证码" autocomplete="off"
									   onkeyup="value=value.replace(/[^\w\.\/]/ig,'')">
							</div>
							<div class="form-group col-8">
								<button type="button" class="btn btn-secondary" id="submittotp">提交</button>
							</div>
						</form>
					</div>

					<div id="webauthn" class="container tab-pane fade">
						<div class="form-group col-8">
							<label>请点击下方按钮进行Webauthn认证。</label>
						</div>
						<div class="form-group col-8">
							<button type="button" class="btn btn-secondary" id="submitwebauthn" onclick="checkregistration()">认证</button>
						</div>
					</div>

				</div>
			</div>
		</div>
	</div>
</div>

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

		$.post('/login', {
			_token : "<?= crsf_token() ?>",
			login : '',
			username : $('#input-username').val(),
			password : md5($('#input-password').val(), "<?= getPasswordClientSalt() ?>")
		}, function(msg) {
			if (msg == 'ok') {
				$.post('/login', {
					status : ''
				}, function(msg) {
					msg = JSON.parse(msg);
					if(msg.mail == false){
						$("[href='#mail']").remove();
						$('#mail').remove();
					}
					if(msg.totp == false){
						$("[href='#totp']").remove();
						$('#totp').remove();
					}
					if(msg.webauthn == false){
						$("[href='#webauthn']").remove();
						$('#webauthn').remove();
					}
					if(msg.mail == true){
						$("[href='#mail']").addClass('active');
						$('#mail').tab('show');
					} else if(msg.totp == true){
						$("[href='#totp']").addClass('active');
						$('#totp').tab('show');
					} else if(msg.webauthn == true){
						$("[href='#webauthn']").addClass('active');
						$('#webauthn').tab('show');
					}
				});
				$('#authModal').modal('show');
			} else if (msg == 'banned') {
				$('#div-username').addClass('has-error');
				$('#help-username').html('该用户已被封停，请联系管理员。');
			} else if (msg == 'expired') {
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
		$('.modal-body').prepend(alert);
	}

	function clearAlerts() {
		$('.alert').alert('close');
	}

	$(document).ready(function() {
		$('#form-login').submit(function(e) {
			e.preventDefault();
			submitLoginPost();
		});

		//设置切换标签栏时清除alert
		$('.nav-item').click(function (e) {
			clearAlerts();
		});

		//邮件验证码提交POST
		$('#submitmail').click(function (e) {
			clearAlerts();
			if($('#input-mail').val().length!=6){
				addAlerts('验证码长度为6位数！','alert-danger');
				return;
			}
			$.post('/login', {
				_token : "<?= crsf_token() ?>",
				vtype : 'mail',
				vcode : $('#input-mail').val(),
				username : $('#input-username').val(),
				password : md5($('#input-password').val(), "<?= getPasswordClientSalt() ?>")
			}, function(msg) {
				if(msg == 'ok'){
					addAlerts('认证成功','alert-success');
					reloadPrev();
				} else if(msg == 'illegal request'){
					addAlerts('非法请求','alert-danger');
				} else{
					addAlerts('验证码错误，请重试。','alert-danger');
				}
				$('#input-mail').val('');
			})
				.fail(function () {
					addAlerts('网络错误！','alert-danger');
				});
		});

		//邮件验证码发送POST
		$('#sendcode').click(function (e) {
			clearAlerts();
			let $this = $(this);
			$.post('/login', {
				_token : "<?= crsf_token() ?>",
				vtype : 'sendmail',
				username : $('#input-username').val(),
				password : md5($('#input-password').val(), "<?= getPasswordClientSalt() ?>")
			}, function(msg) {
				if(msg == 'ok') {
					addAlerts('验证码发送成功！', 'alert-success');
					//为邮件发送设置倒计时
					$this.attr('disabled', true);//设置不可点击
					$this.text("60秒后可重新发送");
					let second = 60;
					let timer = setInterval(() => {
						second -= 1;
						if (second > 0) {
							$this.text(second + "秒后可重新发送");
						} else {
							clearInterval(timer);
							$this.text("发送验证码");
							$this.attr('disabled', false);
						}
					}, 1000);
				}else addAlerts(msg,'alert-danger');
			})
				.fail(function () {
					addAlerts('网络错误！','alert-danger');
				});
		})

		//TOTP验证码提交POST
		$('#submittotp').click(function (e) {
			clearAlerts();
			if($('#input-totp').val().length<6){
				addAlerts('验证码长度为6位数！','alert-danger');
				return;
			}
			$.post('/login', {
				_token : "<?= crsf_token() ?>",
				vtype : 'totp',
				vcode : $('#input-totp').val(),
				username : $('#input-username').val(),
				password : md5($('#input-password').val(), "<?= getPasswordClientSalt() ?>")
			}, function(msg) {
				if(msg == 'ok'){
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
		});


	});

	//                           以下为Webauthn所使用的函数
	/**
	 * checks a FIDO2 registration
	 * @returns {undefined}
	 */
	function checkregistration() {
		clearAlerts();

		if (!window.fetch || !navigator.credentials || !navigator.credentials.create) {
			addAlerts('当前浏览器不支持Webauthn，请更换浏览器重试！','alert-danger');
			return;
		}

		// get default args
		let formdata = new FormData();
		formdata.append("_token","<?= crsf_token() ?>");
		formdata.append("vtype","webauthn");
		formdata.append("type","getGetArgs");
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
			console.log(getCredentialArgs);
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
	//                             以上为Webauthn使用的函数

</script>
<?php echoUOJPageFooter() ?>
