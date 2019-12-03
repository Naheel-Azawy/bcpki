const print = s => console.log(s);
Helper = {
    buildCert: async function(instance, h) {
        return {
            version: await instance.get_cert_version(h),
            algor_ident: await instance.get_cert_algor_ident(h),
            valid_to: await instance.get_cert_valid_to(h),
            subject_name: await instance.get_cert_subject_name(h),
            public_key: await instance.get_cert_public_key(h),
            issuer_id: await instance.get_cert_issuer_id(h),
            subject_id: await instance.get_cert_subject_id(h),
            signature: await instance.get_cert_signature(h),
            exist: await instance.get_cert_exist(h)
        };
    },

    getAllCerts: async function(instance) {
        let count = await instance.get_certs_count();
        let certs = {};
        for (let i = 0; i < count; ++i) {
            let h = await instance.get_cert_hash(i);
            if (h) {
                certs[h] = await Helper.buildCert(instance, h);
            }
        }
        return certs;
    },

    getCRL: async function(instance) {
        let count = await instance.get_crl_count();
        let certs = {};
        for (let i = 0; i < count; ++i) {
            let h = await instance.get_revoked_cert_hash(i);
            if (h) {
                certs[h] = true;
            }
        }
        return certs;
    },

    getCerts: async function(instance) {
        let certs = await Helper.getAllCerts(instance);
        let crl   = await Helper.getCRL(instance);
        let res   = {};
        for (let h of Object.keys(certs)) {
            if (!crl[h]) {
                res[h] = certs[h];
            }
        }
        return res;
    },

    hash: function(x509) {
        let tmp = [
            x509.subject_name,
            x509.public_key
        ];
        return md5(JSON.stringify(tmp));
    },

    enroll: async function(instance, x509) {
        let h = await Helper.hash(x509);
        await instance.enroll(h,
                              x509.algor_ident,
                              x509.valid_to,
                              x509.subject_name,
                              x509.public_key,
                              x509.subject_id,
                              x509.signature, {
                                  from: App.account
                              });
        App.reloadCerts();
    },

    revoke: async function(instance, hash) {
        await instance.revoke(hash, {
            from: App.account
        });
        App.reloadCerts();
    },

    verify: async function(instance, hash) {
        await instance.get_cert(hash, {
            from: App.account
        });
        //App.reloadCerts();
    },

    save: async function(instance, hash) {
        await instance.save(hash, {
            from: App.account
        });
        //App.reloadCerts();
    },

    test: async function(instance) {
        let certs = [
            {
                algor_ident: 'sha256WithRSAEncryption',
                valid_to: '2020-10-20',
                subject_name: 'Security Foundation',
                public_key: '00:c9:22:69:31:8a:d6:6c:ea:da:c3:7f:2c:ac:a5',
                issuer_id: '0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1',
                subject_id: '12345',
                signature: '8b:c3:ed:d1:9d:39:6f:af:40:72:bd:1e:18:5e:30'
            },
            {
                algor_ident: 'sha256WithRSAEncryption',
                valid_to: '2020-03-28',
                subject_name: 'Alice Foundation',
                public_key: '00:c9:22:69:31:8a:d6:6c:ea:da:c3:7f:2c:ac:a5',
                issuer_id: '0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1',
                subject_id: '12346',
                signature: '8b:c3:ed:d1:9d:39:6f:af:40:72:bd:1e:18:5e:30'
            },
            {
                algor_ident: 'sha256WithRSAEncryption',
                valid_to: '2020-01-01',
                subject_name: 'Bob Foundation',
                public_key: '00:c9:22:69:31:8a:d6:6c:ea:da:c3:7f:2c:ac:a5',
                issuer_id: '0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1',
                subject_id: '12347',
                signature: '8b:c3:ed:d1:9d:39:6f:af:40:72:bd:1e:18:5e:30'
            }
        ];
        for (let c of certs) {
            await Helper.enroll(instance, c);
        }
    },

    download: function(filename, text) {
        let pom = document.createElement('a');
        pom.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(text));
        pom.setAttribute('download', filename);

        if (document.createEvent) {
            let event = document.createEvent('MouseEvents');
            event.initEvent('click', true, true);
            pom.dispatchEvent(event);
        } else {
            pom.click();
        }
    }

};

App = {
    web3Provider: null,
    contracts: {},
    account: 0x0,
    loading: false,
    web3Url: "http://localhost:8545",

    init: function() {
        return App.initWeb3();
    },

    initWeb3: function() {
        // initialize web3
        if (typeof web3 !== 'undefined') {
            // reuse the provider of the Web3 object injected by Metamask
            App.web3Provider = window.ethereum;
            print("Using Metamask's web3");
        } else {
            //create a new provider and plug it directly into our local node
            App.web3Provider = new Web3.providers.HttpProvider(App.web3Url);
            print(`Using ${App.web3Url}`);
        }
        web3 = new Web3(App.web3Provider);
        App.displayAccountInfo();
        return App.initContract();
    },

    displayAccountInfo: function() {
        web3.eth.getCoinbase(function(err, account) {
            if(err === null) {
                //print(`Account: ${account}`);
                App.account = account;
                $('#account').text(account);
                web3.eth.getBalance(account, function(err, balance) {
                    if (err === null) {
                        $('#accountBalance').text(web3.fromWei(balance, "ether") + " ETH");
                    }
                });
            }
        });
    },

    listenToEvents: function() {
      // App.contracts.CA.deployed().then(function(instance) {
      //   instance.verLog({}, {}).watch(function(error, event) {
      //     if (!error) {
      //       console.log(event.args.s)
      //     } else {
      //       console.error(error);
      //     }
      //   });
      // });
    },

    initContract: function() {
        $.getJSON('CA.json', function(contArtifact) {
            // get the contract artifact file and use it to instantiate a truffle contract abstraction
            App.contracts.CA = TruffleContract(contArtifact);
            // set the provider for our contracts
            App.contracts.CA.setProvider(App.web3Provider);
            // listen to events
            //App.listenToEvents();
            // retrieve the article from the contract
            return App.reloadCerts();
        });
    },

    reloadCerts: async function() {
        // avoid reentry
        if(App.loading) {
            return;
        }
        App.loading = true;

        // refresh account information because the balance might have changed
        App.displayAccountInfo();

        let contractInstance = await App.contracts.CA.deployed();
        let certs = await Helper.getCerts(contractInstance);

        // retrieve the article placeholder and clear it
        $('#articlesRow').empty();
        for(let h of Object.keys(certs)) {
            App.displayCert(certs[h]);
        }
        App.loading = false;

    },

    displayCert: function(c) {
        //print(c)
        var articlesRow = $('#articlesRow');

        var articleTemplate = $("#articleTemplate");
        articleTemplate.find('.panel-title').text(c.subject_name);

        articleTemplate.find('.cert_subject_id').text(c.subject_id);
        articleTemplate.find('.cert_subject_name').text(c.subject_name);
        articleTemplate.find('.cert_valid_to').text(c.valid_to);
        articleTemplate.find('.cert_public_key').text(c.public_key);
        articleTemplate.find('.cert_signature').text(c.signature);
        articleTemplate.find('.btn-buy').attr('data-id', Helper.hash(c));

        articlesRow.append(articleTemplate.html());
    },

    enrollCert: async function() {
        let c = {
            algor_ident: 'sha256WithRSAEncryption',
            subject_id: $('#cert_subject_id').val(),
            subject_name: $('#cert_subject_name').val(),
            valid_to: $('#cert_valid_to').val(),
            public_key: $('#cert_public_key').val(),
            signature: $('#cert_signature').val()
        };
        print(c);
        await Helper.enroll(await App.contracts.CA.deployed(), c);
    },

    genKeys: function() {
        forge.pki.rsa.generateKeyPair({bits: 2048, e: 0x10001}, (err, keypair) => {
            let public  = forge.pki.getPublicKeyFingerprint(keypair.publicKey, {encoding: 'hex', delimiter: ':'});
            let private = forge.pki.privateKeyToPem(keypair.privateKey);
            $('#cert_public_key').val(public);
            Helper.download("bcpki-private-key.txt", private);
        });
    },

    revokeCert: async function() {
        event.preventDefault();
        let hash = $(event.target).data('id');
        await Helper.revoke(await App.contracts.CA.deployed(), hash);
    },

    downloadCert: async function() {
        event.preventDefault();
        let hash = $(event.target).data('id');
        let instance = await App.contracts.CA.deployed();
        let c = await Helper.buildCert(instance, hash);
        Helper.download("bcpki-certificate.json", JSON.stringify(c, null, 4));
    },

    verifyCert: async function() {
        let c = {
            algor_ident: 'sha256WithRSAEncryption',
            subject_id: $('#cert_subject_idv').val(),
            subject_name: $('#cert_subject_namev').val(),
            valid_to: $('#cert_valid_tov').val(),
            public_key: $('#cert_public_keyv').val(),
            signature: $('#cert_signaturev').val()
        };
        //print(c)
        let hash = Helper.hash(c);
        print(hash);
        let instance = await App.contracts.CA.deployed();
        //print(instance)
        let ans = await instance.verify(hash, {
            from: App.account
        });

        console.log(ans);
    }
};

$(function() {
    $(window).load(function() {
        App.init();
    });
});

async function test() {
    await Helper.test(await App.contracts.CA.deployed());
}
