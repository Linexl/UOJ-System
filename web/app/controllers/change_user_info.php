<?php
require_once $_SERVER['DOCUMENT_ROOT'].'/app/vendor/webauthn/WebAuthn.php';
	if (!Auth::check()) {
		redirectToLogin();
	}
	function handlePost() {
		global $myUser;
		if (!isset($_POST['old_password'])) {
			return '无效表单';
		}
		$old_password = $_POST['old_password'];
		if (!validatePassword($old_password) || !checkPassword($myUser, $old_password)) {
			return "失败：密码错误。";
		}
		if ($_POST['ptag']) {
			$password = $_POST['password'];
			if (!validatePassword($password)) {
				return "失败：无效密码。";
			}
			$password = getPasswordToStore($password, $myUser['username']);
			DB::update("update user_info set password = '$password' where username = '{$myUser['username']}'");
		}

		$email = $_POST['email'];
		if (!validateEmail($email)) {
			return "失败：无效电子邮箱。";
		}
		$esc_email = DB::escape($email);
		DB::update("update user_info set email = '$esc_email' where username = '{$myUser['username']}'");

		if ($_POST['Qtag']) {
			$qq = $_POST['qq'];
			if (!validateQQ($qq)) {
				return "失败：无效QQ。";
			}
			$esc_qq = DB::escape($qq);
			DB::update("update user_info set qq = '$esc_qq' where username = '{$myUser['username']}'");
		} else {
			DB::update("update user_info set QQ = NULL where username = '{$myUser['username']}'");
		}
		if ($_POST['sex'] == "U" || $_POST['sex'] == 'M' || $_POST['sex'] == 'F') {
			$sex = $_POST['sex'];
			$esc_sex = DB::escape($sex);
			DB::update("update user_info set sex = '$esc_sex' where username = '{$myUser['username']}'");
		}
		
		if (validateMotto($_POST['motto'])) {
			$esc_motto = DB::escape($_POST['motto']);
			DB::update("update user_info set motto = '$esc_motto' where username = '{$myUser['username']}'");
		}
		
		return "ok";
	}
    function setRecovery($username){
        $rec1=uojRandRec();
        $rec2=uojRandRec();
        $rec3=uojRandRec();
        $rec4=uojRandRec();
        DB::update("update user_2fa set rec = 'open' where username = '$username'");
        DB::update("update user_2fa set rec1 = '$rec1' where username = '$username'");
        DB::update("update user_2fa set rec2 = '$rec2' where username = '$username'");
        DB::update("update user_2fa set rec3 = '$rec3' where username = '$username'");
        DB::update("update user_2fa set rec4 = '$rec4' where username = '$username'");
        $rec = array(
                "rec1" => $rec1,
                "rec2" => $rec2,
                "rec3" => $rec3,
                "rec4" => $rec4,
        );
        return $rec;
    }
    function handle2FAPost(){
        global $myUser;
        $username = $myUser['username'];
        if (!isset($_POST['old_password'])) {
            $return = new stdClass();
            $return->success = false;
            $return->msg = '无效表单';
            return json_encode($return);
        }
        $old_password = $_POST['old_password'];
        if (!validatePassword($old_password) || !checkPassword($myUser, $old_password)) {
            $return = new stdClass();
            $return->success = false;
            $return->msg = '密码错误。';
            return json_encode($return);
        }
        if($_POST['type']=='check'){
            $secret = $_POST['secret'];
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

            $return = new stdClass();
            if($OTP == $_POST['vcode']){
                DB::delete("delete from user_totp where username ='$username'");
                DB::insert("insert into user_totp values ('$username','$secret')");

                if(!DB::selectFirst("select * from user_2fa where username ='$username'")) {
                    DB::insert("insert into user_2fa (username) values ('$username')");
                }
                $result = DB::selectFirst("select * from user_2fa where username ='$username'");
                if($result['totp']=='close'&&$result['webauthn']=='close'){
                    $return->rec=setRecovery($username);
                }
                DB::update("update user_2fa set totp = 'open' where username = '$username'");
                $return->msg = 'ok';
            }else{
                $return->msg = 'failed';
            }
            return json_encode($return);
        }elseif ($_POST['type']=='close_totp'){
            DB::delete("delete from user_totp where username ='$username'");
            DB::update("update user_2fa set totp = 'close' where username = '$username'");
            $result = DB::selectFirst("select * from user_2fa where username ='$username'");
            if($result['totp']=='close'&&$result['webauthn']=='close'){
                DB::update("update user_2fa set rec='close' where username = '$username'");
            }
            return 'ok';
        }elseif ($_POST['type']=='add_webauthn'){
            try {
                // read get argument and post body
                $vtype = $_POST['vtype'];
                $userVerification = 'required';
                if(isset($_POST['response'])){
                    $post = $_POST['response'];
                    $post = json_decode($post);
                }

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


                if ($vtype === 'getCreateArgs') {
                    $createArgs = $WebAuthn->getCreateArgs($username, $username, $username, 20, false, $userVerification, $crossPlatformAttachment);

                    print(json_encode($createArgs));

                    // save challange to session. you have to deliver it to processGet later.
                    $_SESSION['webauthn-challenge'] = $WebAuthn->getChallenge();

                }elseif ($vtype === 'processCreate') {
                    $return = new stdClass();
                    $clientDataJSON = base64_decode($post->clientDataJSON);
                    $attestationObject = base64_decode($post->attestationObject);
                    $challenge = $_SESSION['webauthn-challenge'];
                    $secret_name = $_POST['secret_name'];

                    if(strlen($secret_name)==0){
                        $return->success = false;
                        $return->msg = '密钥名称不能为空';
                        return json_encode($return);
                    }elseif(strlen($secret_name)>=10){
                        $return->success = false;
                        $return->msg = '密钥名称应小于10字符！';
                        return json_encode($return);
                    }
//                     processCreate returns data to be stored for future logins.
//                     in this example we store it in the php session.
//                     Normaly you have to store the data in a database connected
//                     with the user name.
                    $data = $WebAuthn->processCreate($clientDataJSON, $attestationObject, $challenge, $userVerification === 'required', false, false);

                    addCredentialId($username,$secret_name,$data->credentialId,$data->credentialPublicKey,$data->attestationFormat);

                    if(!DB::selectFirst("select * from user_2fa where username ='$username'")) {
                        DB::insert("insert into user_2fa (username) values ('$username')");
                    }
                    $result = DB::selectFirst("select * from user_2fa where username ='$username'");
                    if($result['totp']=='close'&&$result['webauthn']=='close'){
                        $return->rec=setRecovery($username);
                    }
                    if($result['webauthn']=='close'){
                        DB::update("update user_2fa set webauthn = 'open' where username = '$username'");
                        $return->open = true;
                    }else $return->open = false;

                    unset($_SESSION['webauthn-challenge']);

                    $return->success = true;
                    print(json_encode($return));
                }
            }catch (Throwable $ex) {
                $return = new stdClass();
                $return->success = false;
                $return->msg = $ex->getMessage();
                return json_encode($return);
            }
        }elseif ($_POST['type'] == 'getstatus'){
            $all_status = DB::selectFirst("SELECT * FROM user_2fa WHERE username = '$username'");
            $totp_status = DB::selectFirst("SELECT * FROM user_totp WHERE username = '$username'");
            if(!$totp_status)$totp_status='false';
            else $totp_status='true';
            $webauthn_status = DB::selectALL("SELECT * FROM user_webauthn WHERE username = '$username'");
            $webauthn_data = array();
            foreach ($webauthn_status as $row){
                $webauthn_data[] = array(
                    "username" => $row["username"],
                    "secret_name" => $row["secret_name"],
                    "credentialId" => $row["credentialId"],
                    "attestationFormat" => $row["attestationFormat"],
                    "create_time" => $row["create_time"]
                );
            }
            $return = array(
                    "success" => 'true',
                    "totp" => $all_status['totp'],
                    "webauthn" => $all_status['webauthn'],
                    "rec" => $all_status['rec'],
                    "totp_data" => $totp_status,
                    "webauthn_data" => $webauthn_data
            );
            return json_encode($return);
        }elseif ($_POST['type'] == 'webauthn_delete'){
            $return = new stdClass();
            $credentialId=$_POST['credentialId'];
            DB::delete("delete from user_webauthn where username ='$username' and credentialId = '$credentialId'");
            if(!DB::selectFirst("select * from user_webauthn where username ='$username'")){
                $result = DB::selectFirst("select * from user_2fa where username ='$username'");
                if(!$result) {
                    DB::insert("insert into user_2fa (username) values ('$username')");
                }elseif($result['totp']=='close'){
                    DB::update("update user_2fa set webauthn = 'close',rec='close' where username = '$username'");
                }else DB::update("update user_2fa set webauthn = 'close' where username = '$username'");
                $return->empty= true;
            }else $return->empty= false;
            $return->success= true;
            return  json_encode($return);
        }elseif ($_POST['type'] == 'reset_rec'){
            $return = new stdClass();
            $result = DB::selectFirst("select * from user_2fa where username ='$username'");
            if($result['rec']=='close'){
                $return->success='false';
                return json_encode($return);
            }else{
                $return->success= true;
                $return->rec=setRecovery($username);
            }
            return  json_encode($return);
        }
    }

    function addCredentialId($username,$secret_name,$credentialId,$credentialPublicKey,$attestationFormat){
        $credentialId = bin2hex($credentialId);
        $credentialPublicKey = base64_encode($credentialPublicKey);
        DB::insert("INSERT INTO user_webauthn VALUES ('$username','$secret_name','$credentialId','$credentialPublicKey','$attestationFormat',now())");
    }
    if (isset($_POST['change'])) {
        echo handlePost();
        die();
    }
    if (isset($_POST['type'])) {
        echo handle2FAPost();
        die();
    }
?>
<?php
	$REQUIRE_LIB['dialog'] = '';
	$REQUIRE_LIB['md5'] = '';
?>
<?php echoUOJPageHeader(UOJLocale::get('modify my profile')) ?>
<h2 class="page-header"><?= UOJLocale::get('modify my profile') ?></h2>
<div class="row">
    <div class="col-4">
        <form id="form-update" class="form-horizontal">
<!--            <h4>--><?//= UOJLocale::get('please enter your password for authorization') ?><!--</h4>-->
            <h4>验证密码</h4>
            <div id="div-old_password" class="form-group row">
                <label for="input-old_password" class="col-sm-3 control-label"><?= UOJLocale::get('password') ?></label>
                <div class="col-sm-9">
                    <input type="password" class="form-control" name="old_password" id="input-old_password" placeholder="<?= UOJLocale::get('enter your password') ?>" maxlength="20" />
                    <span class="help-block" id="help-old_password"></span>
                </div>
            </div>
<!--            <h4>--><?//= UOJLocale::get('please enter your new profile') ?><!--</h4>-->
            <h4>个人信息</h4>
            <div id="div-email" class="form-group row">
                <label for="input-email" class="col-sm-3 control-label"><?= UOJLocale::get('email') ?></label>
                <div class="col-sm-9">
                    <input type="email" class="form-control" name="email" id="input-email" value="<?=$myUser['email']?>" placeholder="<?= UOJLocale::get('enter your email') ?>" maxlength="50" />
                    <span class="help-block" id="help-email"></span>
                </div>
            </div>
            <div id="div-qq" class="form-group row">
                <label for="input-qq" class="col-sm-3 control-label"><?= UOJLocale::get('QQ') ?></label>
                <div class="col-sm-9">
                    <input type="text" class="form-control" name="qq" id="input-qq" value="<?= $myUser['qq'] != 0 ? $myUser['qq'] : '' ?>" placeholder="<?= UOJLocale::get('enter your QQ') ?>" maxlength="50" />
                    <span class="help-block" id="help-qq"></span>
                </div>
            </div>
            <div id="div-sex" class="form-group row">
                <label for="input-sex" class="col-sm-3 control-label"><?= UOJLocale::get('sex') ?></label>
                <div class="col-sm-9">
                    <select class="form-control" id="input-sex"  name="sex">
                        <option value="U"<?= Auth::user()['sex'] == 'U' ? ' selected="selected"' : ''?>><?= UOJLocale::get('refuse to answer') ?></option>
                        <option value="M"<?= Auth::user()['sex'] == 'M' ? ' selected="selected"' : ''?>><?= UOJLocale::get('male') ?></option>
                        <option value="F"<?= Auth::user()['sex'] == 'F' ? ' selected="selected"' : ''?>><?= UOJLocale::get('female') ?></option>
                    </select>
                </div>
            </div>
            <div id="div-motto" class="form-group row">
                <label for="input-motto" class="col-sm-3 control-label"><?= UOJLocale::get('motto') ?></label>
                <div class="col-sm-9">
                    <textarea class="form-control" id="input-motto"  name="motto"><?=HTML::escape($myUser['motto'])?></textarea>
                    <span class="help-block" id="help-motto"></span>
                </div>
            </div>
            <div class="form-group">
                <div class="col-sm-12">
                    <p class="form-control-static"><strong><?= UOJLocale::get('change avatar help') ?></strong></p>
                </div>
            </div>
            <h4>安全信息</h4>
            <div id="div-password" class="form-group row">
                <label for="input-password" class="col-sm-3 control-label"><?= UOJLocale::get('new password') ?></label>
                <div class="col-sm-9">
                    <input type="password" class="form-control" id="input-password" name="password" placeholder="<?= UOJLocale::get('enter your new password') ?>" maxlength="20" />
                    <input type="password" class="form-control top-buffer-sm" id="input-confirm_password" placeholder="<?= UOJLocale::get('re-enter your new password') ?>" maxlength="20" />
                    <span class="help-block" id="help-password"><?= UOJLocale::get('leave it blank if you do not want to change the password') ?></span>
                </div>
            </div>
            <h4>双因素认证</h4>
            <div class="col-12">
                <button type="button" class="btn btn-primary" id="manage_2fa">两步验证设置</button>
            </div>
            <div class="form-group" style="margin-top: 50px">
                <div class="col-sm-12">
                    <button type="submit" id="button-submit" class="btn btn-secondary"><?= UOJLocale::get('submit') ?></button>
                </div>
            </div>
        </form>
    </div>
    <div id="twofa" style="display: none" class="col-7 offset-1">
        <h4>两步验证</h4>
        <p>当前状态：<span class="text-danger" id="status-2fa">未启用</span></p>
        <!-- Nav tabs -->
        <ul class="nav nav-tabs" role="tablist">
            <li class="nav-item"><a class="nav-link active" data-toggle="tab" href="#totp">TOTP</a></li>
            <li class="nav-item"><a class="nav-link" data-toggle="tab" href="#webauthn">WebAuthn</a></li>
            <li class="nav-item"><a class="nav-link" data-toggle="tab" href="#recovery">Recovery</a></li>
        </ul><br>
        <!-- Tab panes -->
        <div class="tab-content">
            <div id="totp" class="container tab-pane show active">
                <div class="input-group">
                    <button type="button" class="btn btn-info" id="open_totp">启用 TOTP</button>
                    <button type="button" class="btn btn-danger" id="close_totp">停用 TOTP</button>
                </div>
                <div id="guide" style="display: none">
                    <br><p>通过以下步骤来启用双重验证：</p>
                    <ol class="list">
                        <li>
                            <p>下载或打开具备双重验证功能的验证器应用：</p>
                            <ul>
                                <li><strong>Microsoft Authenticator</strong>： <a href="//go.microsoft.com/fwlink/?Linkid=825072">Android</a> 和 <a href="//go.microsoft.com/fwlink/?Linkid=825073">iOS</a></li>
                                <li><strong>Google Authenticator</strong>： <a href="//play.google.com/store/apps/details?id=com.google.android.apps.authenticator2&amp;hl=en">Android</a> 和 <a href="//itunes.apple.com/us/app/google-authenticator/id388497605?mt=8">iOS</a></li>
                                <li><strong>其他应用</strong>：微信小程序搜索“2FA验证器”、<a href="//f-droid.org/F-Droid.apk">FreeOTP</a>(APK安装包)</li>
                            </ul>
                        </li><br>
                        <li>
                            <p>扫描下面的二维码，或者输入这个密钥 <kbd id="totp_code"></kbd>到您的验证器（忽略空格）。</p>
                            <div id="qrcode"></div>
                        </li>
                        <li>
                            <p>当您扫描或者输入上面的密钥后，您的验证器应用将提供一个验证码，将验证码输入到下面的确认框。</p>
                            <label>验证码</label><br>
                            <input autocomplete="off" id="input_code" maxlength="6"><br><br>
                            <button type="button" class="btn btn-primary" id="check_totp">验证</button>
                        </li>
                    </ol>
                </div>
            </div>

            <div id="webauthn" class="container tab-pane fade">
                <div class="input-group">
                    <input type="text" id="input_name" autocomplete="off" maxlength="9" class="form-control col-4" placeholder="请输入密钥名称" style="-webkit-border-radius: 3px;">&nbsp;
                    <button type="button" class="btn btn-success" id="add_webauthn" onclick="webauthn_add()">添加</button>&nbsp;
                </div>
                <table class="table table-striped table-bordered"style="margin-top: 30px">
                    <thead>
                    <tr>
                        <th scope="col">密钥名称</th>
                        <th scope="col">创建时间</th>
                        <th scope="col">认证平台</th>
                        <th scope="col">操作</th>
                    </tr>
                    </thead>
                    <tbody>

                    </tbody>
                </table>
            </div>

            <div id="recovery" class="container tab-pane fade">
                <p id="tip_rec" style="display: none">您当前未开启任何双因素认证选项，恢复码将在您开启任一后可用。</p>
                <button type="button" class="btn btn-warning" id="reset_rec" style="display: none">重置恢复码</button>
                <p id="tip2_rec" style="display: none"><br><strong>注意：每个恢复码仅可使用一次，以后<span class="text-danger">无法</span>访问此恢复码</strong><br><br>以下为您的恢复码，请将其记录到安全的位置。</p>
                <div class="card bg-light text-primary" style="display: none">
                    <div class="card-body" id="code_rec"></div>
                </div>
            </div>
        </div>
    </div>
</div>
<script src="https://cdn.bootcss.com/jquery.qrcode/1.0/jquery.qrcode.min.js"></script>
<script type="text/javascript">
	function validateUpdatePost() {
		var ok = true;
		ok &= getFormErrorAndShowHelp('email', validateEmail);
		ok &= getFormErrorAndShowHelp('old_password', validatePassword);

		if ($('#input-password').val().length > 0)
			ok &= getFormErrorAndShowHelp('password', validateSettingPassword);
		if ($('#input-qq').val().length > 0)
			ok &= getFormErrorAndShowHelp('qq', validateQQ);
		ok &= getFormErrorAndShowHelp('motto', validateMotto);
		return ok;
	}
	function submitUpdatePost() {
		if (!validateUpdatePost())
			return;
		$.post('/user/modify-profile', {
			change   : '',
			etag     : $('#input-email').val().length,
			ptag     : $('#input-password').val().length,
			Qtag     : $('#input-qq').val().length,
			email    : $('#input-email').val(),
			password : md5($('#input-password').val(), "<?= getPasswordClientSalt() ?>"),
			old_password : md5($('#input-old_password').val(), "<?= getPasswordClientSalt() ?>"),
			qq       : $('#input-qq').val(),
			sex      : $('#input-sex').val(),
			motto    : $('#input-motto').val()
		}, function(msg) {
			if (msg == 'ok') {
				BootstrapDialog.show({
					title   : '修改成功',
					message : '用户信息修改成功',
					type    : BootstrapDialog.TYPE_SUCCESS,
					buttons : [{
						label: '好的',
						action: function(dialog) {
							dialog.close();
						}
					}],
					onhidden : function(dialog) {
						window.location.href = '/user/profile/<?=$myUser['username']?>';
					}
				});
			} else {
				BootstrapDialog.show({
					title   : '修改失败',
					message : msg,
					type    : BootstrapDialog.TYPE_DANGER,
					buttons: [{
						label: '好的',
						action: function(dialog) {
							dialog.close();
						}
					}],
				});
			}
		});
	}

    function addAlerts(text,type) {
        let alert = '<div class="alert '+type+' alert-dismissable" role="alert">'+text+
            '<button type="button" class="close" data-dismiss="alert" aria-hidden="true">&times;</button></div>';
        $('.tab-content').prepend(alert);
    }

    function clearAlerts() {
        $('.alert').alert('close');
    }

    function getBase32(){
        var str="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var res="";
        for(var i=0;i<32;i++){
            res+=str[parseInt(31*Math.random())];
        }
        return res;
    }

    function webauthn_delete(credentialId,name) {
        clearAlerts();
        if(!confirm("确认删除秘钥名称为 "+name+" 的记录吗？"))return ;
        $.post('/user/modify-profile', {
            type : 'webauthn_delete',
            credentialId : credentialId,
            old_password : md5($('#input-old_password').val(), "<?= getPasswordClientSalt() ?>")
        }, function(msg) {
            msg = JSON.parse(msg);
            if(msg.success == true){
                addAlerts('删除成功！','alert-success');
                if(msg.empty == true){
                    addAlerts('Webauthn 已停用！','alert-success');
                }
                refresh2FA();
            }else{
                if(msg.msg){
                    addAlerts('密码错误！','alert-danger');
                }
                addAlerts('删除失败！','alert-danger');
            }
        })
            .fail(function () {
            addAlerts('网络错误！','alert-danger');
        });
    }

    function webauthn_add() {
        clearAlerts();
        var secret = $('#input_name').val();
        if(secret.length == 0){
            addAlerts('密钥名称不能为空！','alert-danger');
        }else if(secret.length >= 10){
            addAlerts('密钥名称应小于10字符！','alert-danger');
        }else newregistration();
    }

    function refresh2FA() {
        var check='false';
        $.ajaxSettings.async = false;
        $.post('/user/modify-profile', {
            type : 'getstatus',
            old_password : md5($('#input-old_password').val(), "<?= getPasswordClientSalt() ?>")
        }, function(msg) {
            msg=JSON.parse(msg);
            if(msg.success==false){
                return ;
            }
            if(msg.totp=='close'){
                $('#open_totp').show();
                $('#close_totp').hide();
            }else{
                $('#open_totp').hide();
                $('#close_totp').show();
            }

            if(msg.rec=='open'){
                $('#reset_rec').show();
                $('.card').hide();
                $('#tip2_rec').hide();
                $('#status-2fa').html('已启用').removeClass('text-danger').addClass('text-success');
                $('a[href="#recovery"]').show();
            }else{
                $('#reset_rec').hide();
                $('#tip_rec').show();
                $('.card').hide();
                $('#tip2_rec').hide();
                $('#status-2fa').html('未启用').removeClass('text-success').addClass('text-danger');
                $('a[href="#recovery"]').hide();
            }

            if(msg.webauthn=='close'){
                $('#open_webauthn').show();
                $('#close_webauthn').hide();
            }else{
                $('#open_webauthn').hide();
                $('#close_webauthn').show();
            }
            $('tbody').empty();
            for(var i=0;i<msg.webauthn_data.length;i++){
                var data=msg.webauthn_data[i];
                $('tbody').append(
                    '<tr>'
                    +'<th scope="row">'+data.secret_name+'</th>'
                    +'<td>'+data.create_time+'</td>'
                    +'<td>'+data.attestationFormat+'</td>'
                    +'<td>'+'<button type="button" class="btn btn-danger" onclick="webauthn_delete(this.name,\''+data.secret_name+'\')"  name='+data.credentialId+'>删除</button>'+'</td>'
                    +'</tr>'
                )
            }
            check='true';
        })
            .fail(function () {
                addAlerts('网络错误！','alert-danger');
            });
        $.ajaxSettings.async = true;
        return check;
    }

    $(document).ready(function(){
        $('#form-update').submit(function(e) {
            submitUpdatePost();
            e.preventDefault();
        });

        //设置切换标签栏时清除alert
        $('.nav-item').click(function (e) {
            clearAlerts();
        });

        $('#manage_2fa').click(function (e) {
            clearAlerts();
            //get info from server and hide something
            if(refresh2FA()=='true'){
                $('#twofa').toggle();
            }else {
                BootstrapDialog.show({
                    title   : '密码错误',
                    message : '请检查您是否输入了正确的密码！',
                    type    : BootstrapDialog.TYPE_DANGER,
                    buttons: [{
                        label: '好的',
                        action: function(dialog) {
                            dialog.close();
                        }
                    }],
                });
            }
        });

        $('#open_totp').click(function (e) {
            clearAlerts();
            var key = getBase32();
            var tip = "";
            $("#guide").show();
            for(var i=0;i<8;i++){
                if(i)tip+=" ";
                tip+=key.substring(4*i,4*i+4);
            }
            $('#totp_code').attr("name",key).text(tip);
            $('#qrcode').html('').qrcode({
                render: "canvas",
                width: 200,
                height: 200,
                text: "otpauth://totp/UOJ:"+"<?= Auth::id() ?>"+"?secret="+key+"&issuer=UOJ&digits=6"
            });
            $('#input_code').focus();
        });
        $('#check_totp').click(function (e) {
            clearAlerts();
            var code=$('#input_code').val();
            if(code.length!=6){
                addAlerts('验证码是6位的！','alert-danger');
                return ;
            }
            $.post('/user/modify-profile', {
                type : 'check',
                secret : $('#totp_code').attr("name"),
                vcode : code,
                old_password : md5($('#input-old_password').val(), "<?= getPasswordClientSalt() ?>")
            }, function(msg) {
                msg = JSON.parse(msg);
                if (msg.msg == 'ok') {
                    refresh2FA();
                    addAlerts('TOTP 已开启！','alert-success');
                    if(msg.rec!=undefined){
                        $('#tip_rec').hide();
                        $('.card').show();
                        $('#tip2_rec').show();
                        $('#code_rec').html(msg.rec.rec1+"<br>"+msg.rec.rec2+"<br>"+msg.rec.rec3+"<br>"+msg.rec.rec4+"<br>");
                        $('a[href="#recovery"]').tab('show');
                    }
                    $("#guide").hide();
                } else{
                    if(msg.msg != 'failed'){
                        addAlerts('密码错误！','alert-danger');
                    }
                    addAlerts('验证失败！请重试。','alert-danger');
                }
            })
                .fail(function () {
                    addAlerts('网络错误！','alert-danger');
                });
        });
        $('#close_totp').click(function (e) {
            clearAlerts();
            $.post('/user/modify-profile', {
                type : 'close_totp',
                old_password : md5($('#input-old_password').val(), "<?= getPasswordClientSalt() ?>")
            }, function(msg) {
                if (msg == 'ok') {
                    addAlerts('TOTP 已停用！','alert-success');
                    refresh2FA();
                } else{
                    if(msg != 'failed'){
                        addAlerts('密码错误！','alert-danger');
                    }
                    addAlerts('停用失败！','alert-danger');
                }
            })
                .fail(function () {
                    addAlerts('网络错误！','alert-danger');
                });
        });

        $('#reset_rec').click(function (e) {
            clearAlerts();
            $.post('/user/modify-profile', {
                type : 'reset_rec',
                old_password : md5($('#input-old_password').val(), "<?= getPasswordClientSalt() ?>")
            }, function(msg) {
                msg=JSON.parse(msg);
                if(msg.success == true) {
                    if (msg.rec != undefined) {
                        $('#tip_rec').hide();
                        $('.card').show();
                        $('#tip2_rec').show();
                        $('#code_rec').html(msg.rec.rec1 + "<br>" + msg.rec.rec2 + "<br>" + msg.rec.rec3 + "<br>" + msg.rec.rec4 + "<br>");
                        $('a[href="#recovery"]').tab('show');
                        addAlerts('重置成功！','alert-success');
                        return ;
                    }
                }
                if(msg.msg){
                    addAlerts('密码错误！','alert-danger');
                }else addAlerts('未知错误！','alert-danger');
            })
                .fail(function () {
                    addAlerts('网络错误！','alert-danger');
                });
        });
	});

    /**
     * creates a new FIDO2 registration
     * @returns {undefined}
     */
    function newregistration() {
        clearAlerts();

        if (!window.fetch || !navigator.credentials || !navigator.credentials.create) {
            addAlerts('当前浏览器不支持Webauthn，或站点未开启https传输!','alert-danger');
            return;
        }

        // get default args
        let formdata = new FormData();
        formdata.append("type","add_webauthn");
        formdata.append("vtype","getCreateArgs");
        formdata.append("rpid",location.hostname);
        formdata.append("old_password",md5($('#input-old_password').val(), "<?= getPasswordClientSalt() ?>"));
        window.fetch('/user/modify-profile',{method:'POST', body:formdata,cache:'no-cache'}).then(function(response) {
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
        }).then(function(createCredentialArgs) {
            console.log(createCredentialArgs);
            return navigator.credentials.create(createCredentialArgs);

            // convert to base64
        }).then(function(cred) {
            return {
                clientDataJSON: cred.response.clientDataJSON  ? arrayBufferToBase64(cred.response.clientDataJSON) : null,
                attestationObject: cred.response.attestationObject ? arrayBufferToBase64(cred.response.attestationObject) : null
            };

            // transfer to server
        }).then(JSON.stringify).then(function(AuthenticatorAttestationResponse) {
            let formdata = new FormData();
            formdata.append("type","add_webauthn");
            formdata.append("vtype","processCreate");
            formdata.append("rpid",location.hostname);
            formdata.append("secret_name",$('#input_name').val());
            formdata.append("response",AuthenticatorAttestationResponse);
            formdata.append("old_password",md5($('#input-old_password').val(), "<?= getPasswordClientSalt() ?>"));
            return window.fetch('/user/modify-profile',{method:'POST', body:formdata,cache:'no-cache'});

            // convert to JSON
        }).then(function(response) {
            return response.json();

            // analyze response
        }).then(function(json) {
            if (json.success) {
                refresh2FA();
                if(json.rec!=undefined){
                    $('#tip_rec').hide();
                    $('.card').show();
                    $('#tip2_rec').show();
                    $('#code_rec').html(json.rec.rec1+"<br>"+json.rec.rec2+"<br>"+json.rec.rec3+"<br>"+json.rec.rec4+"<br>");
                    $('a[href="#recovery"]').tab('show');
                }else addAlerts(json.msg || '记录添加成功','alert-success');
                if(json.open){
                    addAlerts('Webauthn 已开启！','alert-success');
                }
                $('#input_name').val('');
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

