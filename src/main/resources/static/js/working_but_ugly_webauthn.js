
function createCredential(residentKeyRequirement){

    let username = $("#username").val();
    let userHandle = $("#userHandle").val();

    return $.get('/webauthn/attestation/options', null, null, "json").then( options =>{
        let publicKeyCredentialCreationOptions = {
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
            timeout: options.timeout,
            excludeCredentials: options.excludeCredentials.map(credential => {
                return {
                    type: credential.type,
                    id: base64url.decodeBase64url(credential.id)
                }
            }),
            authenticatorSelection: {
                requireResidentKey: residentKeyRequirement,
                userVerification: 'discouraged'
            },
            attestation: options.attestation,
            extensions: options.extensions
        };

        let credentialCreationOptions = {
            publicKey: publicKeyCredentialCreationOptions
        };
        console.log(credentialCreationOptions);

        return navigator.credentials.create(credentialCreationOptions);
    });
}

function getCredential(userVerification){
    return $.get('/webauthn/assertion/options', null, null, "json").then(options => {
        let publicKeyCredentialRequestOptions = {
            challenge: base64url.decodeBase64url(options.challenge),
            timeout: 500000,
//            rpId: options.rpId,
//            allowCredentials: options.allowCredentials.map( credential => {
//                return {
//                    type: credential.type,
//                    id: base64url.decodeBase64url(credential.id)
//                }
//            }),
//            userVerification: userVerification,
//            extensions: options.extensions
        };

        let credentialRequestOptions = {
            publicKey: publicKeyCredentialRequestOptions
        };

        console.log(publicKeyCredentialRequestOptions)
        return navigator.credentials.get(credentialRequestOptions);
    });
}

//$(document).ready(function() {
//
//    $('#creds').click(function(){
//        createCredential(false).then(function (credential) {
//            console.log(credential);
//            $('#clientDataJSON').val(base64url.encodeBase64url(credential.response.clientDataJSON));
//            $('#attestationObject').val(base64url.encodeBase64url(credential.response.attestationObject));
//            $('#clientExtensions').val(JSON.stringify(credential.getClientExtensionResults()));
//            $('#creds').text('Authenticator registered');
//            $('#creds').prop('disabled', true);
//            $('#submit').prop('disabled', false);
//        }).catch(function (e) {
//            console.error("Error:%s, Message:%s", e.name, e.message);
//        });
//    });
//
//    $('#signin').click(function(){
//    console.log("start signin")
//        getCredential("required").then(function (credential) {
//            console.log("Got a credential");
//            console.log(credential);
//            $("#credentialId").val(credential.id);
//            $("#clientDataJSON").val(base64url.encodeBase64url(credential.response.clientDataJSON));
//            $("#authenticatorData").val(base64url.encodeBase64url(credential.response.authenticatorData));
//            $("#signature").val(base64url.encodeBase64url(credential.response.signature));
//            $("#clientExtensions").val(JSON.stringify(credential.getClientExtensionResults()));
//            $('#login-form').submit();
//            console.log("done signin")
//        }).catch(function (e) {
//            console.error("Error: %s, Message: %s", e.name, e.message);
//        });
//    });
//});

function ffsdoit(){
    var options = {
      challenge: new Uint8Array("APzM1AiuRrezcMkzRJoWXw"),
      rpId: "slab.pfudi.de",
      userVerification: "discouraged",
      timeout: 60000,
      allowCredentials:[
        {
            transports: ["usb"],
            type: "public-key",
            id: base64url.decodeBase64url("T1WtswhQ1BeOEdqUf0HuM76uDnIUcM1m2cJxZxEYjxA=")
        }
      ]
    };

    navigator.credentials.get({ publicKey: options })
    .then(function (credentialInfoAssertion) {
        console.log("nice")
    })
    .catch(function (err) {
         console.error("error");
         console.error("err:",err);
    });
}

function register(){
    var publicKey = {
      challenge: new Uint8Array("SPzM1AiuRrezcMkzRJoWXw"),
      rp: {
        id:  "slab.pfudi.de",
        name: "slab.pfudi.de"
      },
      user: {
        id: new Uint8Array("testuser"), // id may be generated by the server
        name: "a.user@example.com",
        displayName: "A User",
        icon: "https://example.com/image.png"
      },
        allowCredentials:[
        {
            transports: ["usb"],
            type: "public-key",
            id: base64url.decodeBase64url("T1WtswhQ1BeOEdqUf0HuM76uDnIUcM1m2cJxZxEYjxA=")
        }
        ],

      pubKeyCredParams: [
        {
          type: "public-key",
          alg: -7 // "ES256" as registered in the IANA COSE Algorithms registry
        }
      ],

      excludeCredentials: [],
      attestation: 'direct',
      timeout: 60000,
      extensions: {}
    };

    navigator.credentials.create({ publicKey })
      .then(function (attestation) {
        console.log("registered", attestation)
      }).catch(function (err) {
        console.error(err)
      });
}