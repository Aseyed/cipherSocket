var express = require('express');
var app = express();
var server = require('http').createServer(app);
var io = require('socket.io')(server);
var fs = require('fs');
var forge = require('node-forge')
var rsa = forge.pki.rsa;
var pki = forge.pki;

var bodyParser = require('body-parser');
var content = fs.readFileSync('db.json');
//var content = require('db.json');
var db = JSON.parse(content);

// app.use(express.static('views'));
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


// app.use('/scripts',express.static(__dirname + '/node_modules'));
// app.get('/', function (req, res, next) {
//     res.render('index');
// });

//TODO: make pki
//TODO: generate nonce
//TODO: save shared key
//TODO:


var keypair = rsa.generateKeyPair({bits: 1024, e: 0x10001});
var publicPem = pki.publicKeyToPem(keypair.publicKey);
var privatePem = pki.privateKeyToPem(keypair.privateKey);
var encrypted;
var userdata;

// db.push({
//     'publickeyPem':publicPem,
//     'privatePem':privatePem
// });

//make and send cipher message
function cipherfunc(message, skey, iv) {
    var cipher = forge.rc2.createEncryptionCipher(skey);
    cipher.start(iv);
    cipher.update(forge.util.createBuffer(message));
    cipher.finish();
    encrypted = cipher.output;
    // socket.emit('response', encrypted)
}

io.on('connection', function (client) {
    console.log('Client connected...');

    var skey='';
    var iv='';

    var nonce = Math.random();

    client.on("handshake", function (data) {
     //   console.log(data);
        client.emit('handshake',JSON.stringify({'nonce': nonce, 'pki':publicPem}));
    })

    client.on("setSkey", function (data) {
        var decripted = keypair.privateKey.decrypt(data);
        var content = JSON.parse(decripted);
        if (content.nonce == nonce){
            skey = content.skey;
            iv = content.iv;
            console.log("key shared");
        }
        else
            console.log("Hello Trudy :)");
    })


    // client.on('join', function (data) {
    //     console.log(data);
    // });

    client.on('register', function (data) {
       // console.log(data);

        // encrypted = forge.util.hexToBytes(data);
        var cipher = forge.rc2.createDecryptionCipher(skey);
        cipher.start(iv);
        cipher.update(forge.util.createBuffer(data));
        cipher.finish();
        //console.log(cipher.output);
        userdata = JSON.parse(cipher.output);
        var flag =0;
        //for(var i in db.username) {
        db.forEach(function (element) {
            if (element.UserName === userdata.UserName) {
                console.log('this user already registered');
                cipherfunc('this user already registered', skey, iv);
                client.emit('response', encrypted);
                flag = 1;
            }
        });
        if (!flag){
            // userdata.PublicKey = pki.publicKeyFromPem(userdata.PublicKey);
            db.push(userdata);
            //db.
           // console.log(db);

            fs.writeFileSync("db.json", JSON.stringify(db));

            cipherfunc('registeration done.', skey, iv);
            client.emit('response', encrypted);
        }


    });

    var loginLog = " ";
    var loginmessage = ' ';

    client.on('login', function (data) {
        var cipher = forge.rc2.createDecryptionCipher(skey);
        cipher.start(iv);
        cipher.update(forge.util.createBuffer(data));
        cipher.finish();
       // console.log(cipher.output.data);
        var logindata = JSON.parse(cipher.output.data);
        db.forEach(function (element) {
            if (element.UserName == logindata.UserName) {
                if(element.Password == logindata.Password){
                   // console.log('User is log in');
                    cipherfunc('User is log in', skey, iv);

                    loginLog = encrypted;
                    var md = forge.md.sha256.create();
                    md.update(logindata.message);
                  //  var byte = md
                    var hashhex = md.digest().toHex();

                    //console.log(byte)
                    //console.log(logindata.hashmessage)

                    if (hashhex != logindata.hashmessage) {
                        cipherfunc('No integrity', skey, iv);
                       // console.log('No integrity');
                        loginLog = encrypted;
                      //  console.log(loginLog);
                    }
                    else{
                        var base64 = forge.util.encode64(hashhex);
                        cipherfunc(base64, skey, iv);
                        loginmessage = encrypted;
                        // console.log(loginmessage)
                        console.log('base:', base64);
                    }
                }
                else{
                    cipherfunc('password is not correct', skey, iv);
                }
            }
        });
        if(loginLog === " "){
            cipherfunc('User dose not exist', skey, iv);
            loginLog=encrypted
        }
        client.emit('login', JSON.stringify({'loginLog': loginLog , 'loginmessage' : loginmessage}));
    });

    var authlog = ' ';
    client.on('auth', function (data) {

        var cipher = forge.rc2.createDecryptionCipher(skey);
        cipher.start(iv);
        cipher.update(forge.util.createBuffer(data));
        cipher.finish();

        var authdata = JSON.parse(cipher.output.data)

        db.forEach(function (element) {
            if (element.UserName === authdata.username) {
                var client_publickey = pki.publicKeyFromPem(element.PublicKey);
                var username = authdata.username;

                var md = forge.md.sha1.create();
                md.update(username, 'utf8');
                // console.log(authdata.signature);
                // console.log(md.digest().getByte())
                var verified = client_publickey.verify(md.digest().getByte(), authdata.signature);

                if(verified){
                    cipherfunc('Auth without pass passed', skey, iv);
                    authlog = encrypted;
                }
                else{
                    cipherfunc('Auth without pass failed', skey, iv);
                    authlog = encrypted;
                }
            }
        });
        if(authlog === ' '){
            cipherfunc('user not founded', skey, iv);
            authlog = encrypted;
        }

        client.emit('auth', authlog);

    })
});

var port = process.env.PORT || 2000
server.listen(port, function () {
    console.log('server created')
});