let App = {
    contracts: {},
    contract: null,
    account: 0x0,
    loading: false,
    web3Url: ETH_ADDR.split("@")[0],
    contract_address: ETH_ADDR.split("@")[1],
    certs: [],

    init: async function() {
        await App.initWeb3();
        App.displayAccountInfo();
        return App.initContract();
    },

    initWeb3: async function() {
        let forceHttp = true;
        if (window.ethereum && !forceHttp) {
            window.ethereum = new Web3(window.ethereum);
            await window.ethereum.enable();
            console.log("Using window.ethereum");
        } else if (window.ethereum && !forceHttp) {
            console.log("Using window.ethereum");
            window.ethereum = new Web3(window.ethereum.currentProvider);
        } else {
            let provider = new Web3.providers.HttpProvider(App.web3Url);
            window.ethereum = new Web3(provider);
            console.log(`Using ${App.web3Url}`);
        }
    },

    displayAccountInfo: function() {
        window.ethereum.eth.getCoinbase((err, account) => {
            if(err === null) {
                App.account = account;
                window.ethereum.eth.defaultAccount = account;
                $('#account').text(account);
                window.ethereum.eth.getBalance(account, function(err, balance) {
                    if (err === null) {
                        $('#accountBalance').text(
                            window.ethereum.utils.fromWei(balance, "ether") + " ETH");
                    }
                });
            }
        });
    },

    initContract: function() {
        fetch("build/contracts/CA.json")
            .then(response => {
                if (!response.ok) {
                    throw new Error("HTTP error " + response.status);
                }
                return response.json();
            })
            .then(json => {
                App.json = json;
                // create an instance of the contract
                App.contract =
                    new window.ethereum.eth.Contract(json.abi, App.contract_address);

                App.tcontract = TruffleContract(json);
                App.tcontract.setProvider(window.ethereum.currentProvider);

                App.reloadCerts();
            })
            .catch(e => {
                console.error(e);
                // TODO: show error
            });
    },

    genHash: function(cert) {
        /* Generate a hash of the certificate dict.
          If `cert` is the hash, return it.
          This allows passing either the hash or the cert
          itself in the functions below */
        if (typeof cert === "string") {
            return cert;
        }
        let tmp = (cert.valid_to +
                   cert.public_key +
                   cert.subject_id).replace(/\s+/g, "");
        return forge.md.sha256.create().update(tmp)
            .digest().toHex();
    },

    genKeyPair: function() {
        return new Promise((resolve, reject) => {
            forge.pki.rsa.generateKeyPair({bits: 2048, e: 0x10001}, (err, keypair) => {
                let public = forge.pki.publicKeyToPem(keypair.publicKey);
                public = public.trim().split("\n");
                public.shift();
                public.pop();
                public = public.join("\n");
                let private = forge.pki.privateKeyToPem(keypair.privateKey);
                resolve({
                    public: public,
                    private: private
                });
            });
        });
    },

    getCerts: async function() {
        //let certs = await App.contract.methods.get_certs().call();
        let instance = await App.tcontract.deployed();
        let certs = await instance.get_certs();
        let res = [];
        for (let cert of certs) {
            res.push({
                version: cert[0],
                valid_to: cert[1],
                public_key: cert[2],
                issuer_id: cert[3],
                subject_id: cert[4],
                subject_name: cert[5],
                exist: cert[6],
                wallet_owner: cert[7],
                algor_ident: "sha256WithRSAEncryption", // TODO: implement
            });
        }
        return res;
    },

    reloadCerts: async function() {
        // avoid reentry
        if(App.loading) {
            return;
        }
        App.loading = true;

        // refresh account information because the balance might have changed
        App.displayAccountInfo();

        let list = await App.getCerts();
        App.certs = {};
        for (let c of list) {
            App.certs[App.genHash(c)] = c;
        }

        $('#certsRow').empty();
        for(let h of Object.keys(App.certs).reverse()) {
            App.displayCert(App.certs[h]);
        }
        App.loading = false;
    },

    displayCert: function(c) {
        let hash = App.genHash(c);
        let certsRow = $('#certsRow');
        let certTemplate = $("#certTemplate");
        certTemplate.find('.panel-title').text(hash);
        certTemplate.find('.cert_subject_id').text(c.subject_id);
        certTemplate.find('.cert_subject_name').text(c.subject_name);
        certTemplate.find('.cert_valid_to').text(c.valid_to);
        certTemplate.find('.cert_public_key').text(
            "-----BEGIN PUBLIC KEY-----\n" + c.public_key +
                "\n-----END PUBLIC KEY-----");
        certTemplate.find('.btn-buy').attr('data-id', hash);
        certsRow.append(certTemplate.html());
    },

    enrollCert: async function() {
        let cert = {
            algor_ident: 'sha256WithRSAEncryption',
            subject_id: $('#cert_subject_id').val().trim(),
            subject_name: $('#cert_subject_name').val().trim(),
            valid_to: $('#cert_valid_to').val().trim(),
            public_key: $('#cert_public_key').val().trim()
        };
        let hash = App.genHash(cert);

        /*
        let res = await App.contract.methods
            .enroll(hash,
                    cert.valid_to,
                    cert.public_key,
                    cert.subject_id,
                    cert.subject_name)
            .send({from: App.account});
        */

        let instance = await App.tcontract.deployed();
        let res = await instance
            .enroll(hash,
                    cert.valid_to,
                    cert.public_key,
                    cert.subject_id,
                    cert.subject_name,
                    {from: App.account});

        console.log(hash);
        console.log(res);
        App.reloadCerts();
    },

    genKeys: async function() {
        let subject = $('#cert_subject_id').val();
        if (!subject) {
            return;
        }
        let pair = await App.genKeyPair();
        $('#cert_public_key').val(pair.public);
        App.download(subject + "-bcpki-private-key.txt", pair.private);
    },

    revokeCert: async function() {
        event.preventDefault();
        if (!confirm("Are you sure you want to revoke?")) {
            return;
        }

        let hash = $(event.target).data('id');

        /*
        let res = await App.contract.methods
            .revoke(hash).send({from: App.account});
        */

        let instance = await App.tcontract.deployed();
        let res = await instance
            .revoke(hash, {from: App.account});

        console.log(res);
        App.reloadCerts();
    },

    downloadCert: async function() {
        event.preventDefault();
        let hash = $(event.target).data('id');
        let c = App.certs[hash];
        App.download(c.subject_id + "-bcpki-certificate.json",
                     JSON.stringify(c, null, 4));
    },

    verifyCert: async function() {
        let hash = App.genHash({
            subject_id: $('#cert_subject_idv').val().trim(),
            valid_to: $('#cert_valid_tov').val().trim(),
            public_key: $('#cert_public_keyv').val().trim()
        });
        /*let res = await App.contract.methods
            .verify(hash).call();*/
        let instance = await App.tcontract.deployed();
        let res = await instance.verify(hash);
        console.log(hash);
        console.log(res);
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
    },

    testEnrolls: async function() {
        let certs = [
            {
                algor_ident: "sha256WithRSAEncryption",
                subject_id: "naheel",
                subject_name: "Naheel Faisal Kamal",
                valid_to: "2030-12-12",
                public_key: (await App.genKeyPair()).public
            },
            {
                algor_ident: "sha256WithRSAEncryption",
                subject_id: "iot-ac",
                subject_name: "IoT Air Conditioning",
                valid_to: "2030-12-12",
                public_key: (await App.genKeyPair()).public
            },
            {
                algor_ident: "sha256WithRSAEncryption",
                subject_id: "iot-temp",
                subject_name: "IoT Temperature Sensors",
                valid_to: "2030-12-12",
                public_key: (await App.genKeyPair()).public
            }
        ];

        for (let cert of certs) {
            console.log(cert);
            let instance = await App.tcontract.deployed();
            await instance
                .enroll(App.genHash(cert),
                        cert.valid_to,
                        cert.public_key,
                        cert.subject_id,
                        cert.subject_name,
                        {from: App.account});
        }
        App.reloadCerts();
    },

    testEval: async function() {
        function rand() {
            return (Math.random() * 0xFFFFFF << 0).toString(16)
                .padStart(6, '0');
        }

        let instance = await App.tcontract.deployed();
        let certs = [];

        let get_times = [];
        let enroll_times = [];
        let revoke_times = [];

        let enroll_gas = 0;
        let revoke_gas = 0;

        console.log("=init");
        for (let i = 0; i < 50; ++i) {
            certs.push({
                algor_ident: "sha256WithRSAEncryption",
                subject_id: rand(),
                subject_name: rand(),
                valid_to: "2030-12-12",
                public_key: (await App.genKeyPair()).public
            });
        }

        let t, res;

        console.log("=enroll and get_certs");
        for (let i in certs) {
            let cert = certs[i];

            t = new Date();
            res = await instance
                .enroll(App.genHash(cert),
                        cert.valid_to,
                        cert.public_key,
                        cert.subject_id,
                        cert.subject_name,
                        {from: App.account});
            t = new Date() - t;
            enroll_gas = res.receipt.gasUsed;
            enroll_times.push(t);

            t = new Date();
            res = await instance.get_certs();
            t = new Date() - t;
            get_times.push(t);
            
            console.log(i);
        }

        console.log("=revoke");
        for (let i in certs) {
            let cert = certs[i];

            t = new Date();
            res = await instance
                .revoke(App.genHash(cert),
                        {from: App.account});
            t = new Date() - t;
            revoke_gas = res.receipt.gasUsed;
            revoke_times.push(t);

            console.log(i);
        }

        let get_one_times = [];
        console.log("=one");
        for (let i = 0; i < 50; ++i) {
            t = new Date();
            res = await instance.verify(
                "11d431eb7b633839ffb61979bd6e7d43ece34ea3090bf0368774eb0723cfc76e");
            t = new Date() - t;
            get_one_times.push(t);
        }
        console.log(get_one_times.join(","));

        console.log(get_times.join(","));
        console.log(enroll_times.join(","));
        console.log(revoke_times.join(","));

        console.log(`enroll_gas = ${enroll_gas}`);
        console.log(`revoke_gas = ${revoke_gas}`);

    }

};

$(window).load(App.init);
