print = s => console.log(s);

function download(filename, text) {
    var pom = document.createElement('a');
    pom.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(text));
    pom.setAttribute('download', filename);

    if (document.createEvent) {
        var event = document.createEvent('MouseEvents');
        event.initEvent('click', true, true);
        pom.dispatchEvent(event);
    }
    else {
        pom.click();
    }
}

forge.pki.rsa.generateKeyPair({bits: 2048, e: 0x10001}, (err, keypair) => {
    let public  = forge.pki.getPublicKeyFingerprint(keypair.publicKey, {encoding: 'hex', delimiter: ':'});
    let private = forge.pki.privateKeyToPem(keypair.privateKey);

    print(public);
    print(private);

    download("ppp.txt", private);
});
