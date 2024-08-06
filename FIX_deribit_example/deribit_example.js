const FIXParser = require("fix-over-tcp/fixparser");
const crypto = require("crypto");

const API_KEY = "YOUR-API-KEY(Client Id)";
const API_SECRET = "YOUR-API-SECRET(Client Secret)";
//const DERIBIT_HOST = "test.deribit.com"; // <-- you must be registered on test.deribit.com and API key/secret from test.deribit.com, not from www
const DERIBIT_HOST = "www.deribit.com";
const DERIBIT_PORT = 9881;

const userName = API_KEY;
var timestampInMs = (new Date()).getTime();
var nonceInBase64 = Buffer.from(crypto.randomBytes(32)).toString('base64');
var rawData = timestampInMs + "." + nonceInBase64;
var baseSignatureString = rawData + API_SECRET;
var password = Buffer.from(crypto.createHash("sha256").update(baseSignatureString).digest()).toString('base64');

console.log("Username: " + userName);
console.log("RawData: " + rawData);
console.log("Password: " + password);

const fixParser = new FIXParser.default();
fixParser.fixVersion = 'FIX.4.4';
const Logon = fixParser.createMessage(
    new FIXParser.Field(FIXParser.Fields.MsgType, FIXParser.Messages.Logon),
    new FIXParser.Field(FIXParser.Fields.SenderCompID, 'TestClient'),
    new FIXParser.Field(FIXParser.Fields.TargetCompID, 'DERIBITSERVER'),
    new FIXParser.Field(FIXParser.Fields.MsgSeqNum, fixParser.getNextTargetMsgSeqNum()),
    new FIXParser.Field(FIXParser.Fields.SendingTime, fixParser.getTimestamp()),
    new FIXParser.Field(FIXParser.Fields.HeartBtInt, 60),
    new FIXParser.Field(FIXParser.Fields.RawData, rawData),
    new FIXParser.Field(FIXParser.Fields.Username, userName),
    new FIXParser.Field(FIXParser.Fields.Password, password),
);

//console.log(Logon.encode('|'));

fixParser.connect({
    host: DERIBIT_HOST,
    port: DERIBIT_PORT,
    protocol: 'tcp',
    sender: 'TestClient',
    target: 'DERIBITSERVER',
    fixVersion: 'FIX.4.4',
    heartbeatIntervalMs: 3000,

});

fixParser.on('open', () => {
    console.log('Open');
    fixParser.send(Logon)
    console.log("sent Logon message: ", Logon.encode().toString())
});
fixParser.on("message", (message) => {
    console.log("received message: ", message.description, message.string);
});
fixParser.on('close', () => {
    console.log('Disconnected');
});