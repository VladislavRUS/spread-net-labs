const net = require('net'),
      si = require('systeminformation'),
      readline = require('readline'),
      JsonSocket = require('json-socket'),
      sha256 = require('sha256'),
      constants = require('./constants');

const PORT = 1327;
const HOST = '127.0.0.1';

let uuid;

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

rl.question('Please, enter your name: ', (name) => {
    rl.close();
    connect(name);
});

function connect(name) {

    const socket = new JsonSocket(net.Socket());
    
    socket.connect(PORT, HOST);
    
    socket.on('connect', () => {
        si.system(data => {
            uuid = data.uuid;
            socket.sendMessage({ type: constants.INITIAL_AUTH, data: `${name}:${uuid}`});
        });
    });

    socket.on('message', message => {

        switch(message.type) {
            case constants.KEY_GENERATED: {

                let key = message.data.key;
                let salts = message.data.salts;

                let hashes = [];

                salts.forEach(salt => {
                    let string = name + uuid + key + salt;
                    let hash = sha256(string);

                    hashes.push(hash);
                });

                socket.sendMessage({type: constants.CHECK_HASHES, data: hashes});

                break;
            }
            case constants.AUTH_FAIL: {
                console.log(`Auth failed! Reason: ${message.data}`);
                break;
            }
            case constants.AUTH_SUCCESS: {
                console.log('You have been successfully logged in!');
                break;
            }
        }
    });
    
    socket.on('error', () => {
        console.log('Connection closed');
    });
}