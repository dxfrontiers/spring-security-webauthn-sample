function createCredential(){

    let username = $("#username").val();
    let userHandle = $("#userHandle").val();

    return $.get('/webauthn/attestation/options', null, null, "json").then( options =>{
        console.log(options)
        let ccOptions = {
            rp: {
                id: options.rp.id,
                name: options.rp.name
            },
            user: {
                id: base64url.decodeBase64url(userHandle),
                name: username,
                displayName: username
            },
            challenge: base64url.decodeBase64url(options.challenge),
            pubKeyCredParams: options.pubKeyCredParams,
            authenticatorSelection: {
                requireResidentKey: false,
                userVerification: 'discouraged'
            },
        };
        return navigator.credentials.create({ publicKey: ccOptions});
    });
}

function getCredential(){
    return $.get('/webauthn/assertion/options', null, null, "json").then(options => {
        let crOption = {
            challenge: base64url.decodeBase64url(options.challenge),
            timeout: 500000,
            allowCredentials: options.allowCredentials.map( credential => {
                return {
                    type: credential.type,
                    id: base64url.decodeBase64url(credential.id)
                }
            }),
            userVerification: 'discouraged',
        };
        return navigator.credentials.get({publicKey: crOption});
    });
}

$(document).ready(function() {

    $('#creds').click(function(){
        createCredential().then(function (credential) {
            console.log("Created credential: ",credential);
            $('#clientDataJSON').val(base64url.encodeBase64url(credential.response.clientDataJSON));
            $('#attestationObject').val(base64url.encodeBase64url(credential.response.attestationObject));
            $('#clientExtensions').val(JSON.stringify(credential.getClientExtensionResults()));
            $('#creds').text('Authenticator registered');
            $('#creds').prop('disabled', true);
            $('#submit').prop('disabled', false);
        }).catch(function (e) {
            console.error("Error:%s, Message:%s", e.name, e.message);
        });
    });

    $('#signin').click(function(){
        getCredential().then(function (credential) {
            console.log("Got credential: ",credential);
            $("#credentialId").val(credential.id);
            $("#clientDataJSON").val(base64url.encodeBase64url(credential.response.clientDataJSON));
            $("#authenticatorData").val(base64url.encodeBase64url(credential.response.authenticatorData));
            $("#signature").val(base64url.encodeBase64url(credential.response.signature));
            $("#clientExtensions").val(JSON.stringify(credential.getClientExtensionResults()));
            $('#login-form').submit();
        }).catch(function (e) {
            console.error("Error: %s, Message: %s", e.name, e.message);
        });
    });
});
