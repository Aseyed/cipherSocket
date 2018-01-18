var express = require('express');
var app = express();
var server = require('http').createServer(app);
var io = require('socket.io')(server);
var io_client = require('socket.io-client')
var fs = require('fs');
var forge = require('node-forge')
var rsa = forge.pki.rsa;
var pki = forge.pki;

var bodyParser = require('body-parser');
var content = fs.readFileSync('userdb.json');
//var content = require('db.json');
var db = JSON.parse(content);

app.use(express.static('views'));
//app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));
app.use(function (req, res, next) {
    // Website you wish to allow to connect
    res.setHeader('Access-Control-Allow-Origin', '*');
    // Request methods you wish to allow
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, PATCH, DELETE');
    // Request headers you wish to allow
    res.setHeader('Access-Control-Allow-Headers', 'X-Requested-With,content-type');
    // Set to true if you need the website to include cookies in the requests sent
    // to the API (e.g. in case you use sessions)
    res.setHeader('Access-Control-Allow-Credentials', true);
    // Pass to next layer of middleware
    next();
});


app.use('/scripts',express.static(__dirname + '/node_modules'));
app.get('/', function (req, res, next) {
    res.render('index');
});
var rsa = forge.pki.rsa;
var pki = forge.pki;
var skey = forge.random.getBytesSync(16);
var iv = forge.random.getBytesSync(8);

var socket = io_client.connect('http://localhost:2000');
socket.on('connect', function (data) {
    //socket.emit('join', 'Hello World from client');
    socket.emit("handshake", 'Hello Server :)');
});

var serverKey;
socket.on("handshake", function (data) {
    var content = JSON.parse(data);
    var nonce = content.nonce;
    serverKey = pki.publicKeyFromPem(content.pki)

    socket.emit("setSkey", serverKey.encrypt(JSON.stringify({
        'skey': skey,
        'iv': iv,
        'nonce': nonce
    })))
});
var keypair = rsa.generateKeyPair({bits: 1024, e: 0x10001});
var publicPem = pki.publicKeyToPem(keypair.publicKey);
var privatePem = pki.privateKeyToPem(keypair.privateKey);

//console.log(publicPem.toHex())
//document.getElementById("register-submit").onclick="register()";
var username;
var password;
var email;
var message;
app.post('/register', function (req, res) {
// })
// function register() {
    username = req.body.username;
    password = req.body.password;
    email = req.body.email;

    var md = forge.md.sha256.create();
    md.update(password);
    var hashpass = md.digest().toHex();

    reg = {
        'UserName': username,
        'Password': hashpass,
        'Email': email,
        'PublicKey': publicPem
    };
    var cipher = forge.rc2.createEncryptionCipher(skey);
    cipher.start(iv);
    cipher.update(forge.util.createBuffer(JSON.stringify(reg)));
    cipher.finish();
    var encrypted = cipher.output;

    //console.log(JSON.stringify(reg));
    socket.emit('register', encrypted);
    res.redirect('/')
});

socket.on("response", function (data) {
    var md = forge.md.sha256.create();
    md.update(password);
    var hashpass = md.digest().toHex();

    //decryption
    var cipher = forge.rc2.createDecryptionCipher(skey);
    cipher.start(iv);
    cipher.update(forge.util.createBuffer(data));
    cipher.finish();

    var res = cipher.output.data;
    if (res == 'registeration done.') {
        var md = forge.md.sha256.create();
        md.update(password);
        var hashpass = md.digest().toHex();

        var user = {
            'UserName': username,
            'Password': hashpass,
            'pemPublic': publicPem,
            'pemPrivate': privatePem,
            'serverKey': pki.publicKeyToPem(serverKey)
        }

        db.push(user);
        console.log(db);
        fs.writeFileSync("userdb.json", JSON.stringify(db));

        console.log(cipher.output.data);
    }
});

app.post('/login', function (req, res) {

// })
// function login() {
    var username = req.body.username;
    var password = req.body.password;
    var message = req.body.message;

    var md = forge.md.sha256.create();
    md.update(password);
    var hashpass = md.digest().toHex();

    var md = forge.md.sha256.create();
    md.update(message);
    var hashmessage = md.digest().toHex();
    var data = {
        'UserName': username, 'Password': hashpass,
        'message': message, 'hashmessage': hashmessage
    };

    var cipher = forge.rc2.createEncryptionCipher(skey);
    cipher.start(iv);
    cipher.update(forge.util.createBuffer(JSON.stringify(data)));
    cipher.finish();
    var encrypted = cipher.output;
    socket.emit('login', encrypted);

    socket.on('login', function (data) {
        var content = JSON.parse(data);
        var cipher = forge.rc2.createDecryptionCipher(skey);
        cipher.start(iv);
        cipher.update(forge.util.createBuffer(content.loginmessage));
        cipher.finish();

        content.loginmessage = cipher.output.data;
        var message = forge.util.decode64(content.loginmessage);
        //console.log(content.loginmessage)


        var cipher = forge.rc2.createDecryptionCipher(skey);
        cipher.start(iv);
        cipher.update(forge.util.createBuffer(content.loginLog));
        cipher.finish();
        //console.log(cipher.output.data);


        console.log(content.loginmessage + ' decoded from base 64: ' + message);
    });
    res.redirect('/')
});
// var signature;
app.post("/auth", function (req,res) {

    db.forEach(function (element) {
        if (element.UserName === req.body.username) {
            var privatekey = pki.privateKeyFromPem(element.pemPrivate);
            var publickey = pki.publicKeyFromPem(element.pemPublic);
            var username = req.body.username;


            var md = forge.md.sha1.create();
            md.update(username, 'utf8');
            var signature = privatekey.sign(md);

            // console.log(signature);
            // console.log(md.digest().getByte())
            var verified = publickey.verify(md.digest().bytes(), signature);

            console.log(verified);
            var cipher = forge.rc2.createEncryptionCipher(skey);
            cipher.start(iv);
            var data = {
                "username": username,
                "signature": signature
            };
            cipher.update(forge.util.createBuffer(JSON.stringify(data)));
            cipher.finish();
            var encrypted = cipher.output;
            socket.emit('auth',encrypted)


        }
    });

    res.redirect('/');
})

socket.on('auth',function (data) {
    var cipher = forge.rc2.createDecryptionCipher(skey);
    cipher.start(iv);
    cipher.update(forge.util.createBuffer(data));
    cipher.finish();
    console.log(cipher.output.data);
})

var port = process.env.PORT || 3000
server.listen(port, function () {
    console.log('client created')
});