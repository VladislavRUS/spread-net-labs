const net = require('net'),
      JsonSocket = require('json-socket'),
      sha256 = require('sha256'),
      constants = require('./constants');

const PORT = 1327;
const HOST = '127.0.0.1';

let clients = [];

function generateKey() {
    return new Date().getTime();
}

function generateSalt() {
    let salt = '';

    for (let i = 0; i < 64; i++) {
        salt += Math.round(Math.random());
    }

    return salt;
}

const server = net.createServer(socket => {

    socket = new JsonSocket(socket);

    clients.push(socket);

    socket.on('message', message => {

        switch(message.type) {
            case constants.INITIAL_AUTH: {

                socket.name = message.data.split(':')[0];
                socket.uuid = message.data.split(':')[1];
                socket.key = generateKey();
                socket.salts = [];

                for (let i = 0; i < 1000; i++) {
                    socket.salts.push(generateSalt());
                }

                console.log(`Client's info: ${socket.name}, ${socket.uuid}, ${socket.key}`);

                socket.sendMessage({ type: constants.KEY_GENERATED, data: {
                    key: socket.key,
                    salts: socket.salts
                }});

                break;
            }

            case constants.CHECK_HASHES: {
                let key = socket.key;
                let uuid = socket.uuid;
                let name = socket.name;

                let hashes = [];

                socket.salts.forEach(salt => {
                    let string = name + uuid + key + salt;
                    let hash = sha256(string);

                    hashes.push(hash);
                });

                let results = [];
                let clientHashes = message.data;

                if (hashes.length !== clientHashes.length) {
                    socket.sendMessage({type: constants.AUTH_FAIL, data: 'Length of hashes arrays are not equal!'});
                    return;
                }

                for (let i = 0; i < hashes.length; i++) {
                    if (hashes[i] !== clientHashes[i]) {
                        results.push(1);

                    } else {
                        results.push(0);
                    }
                }

                console.log(results.join(', '));

                let sum = results.reduce((first, second) => first + second);

                if (sum === 0) {
                    socket.sendMessage({type: constants.AUTH_SUCCESS});

                } else {
                    socket.sendMessage({type: constants.AUTH_FAIL, data: 'Hashes comparing failed!'});
                }
            }
        }
    });

    socket.on('error', err => {
        console.log(`${socket.name} has disconnected...`);
        clients.splice(clients.indexOf(socket), 1);
    });
});

server.listen(PORT, HOST, () => {
    console.log('Server started');
});