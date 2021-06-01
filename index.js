const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
let publicKey;
let privateKey;

const setup = (location, algorithm = "rsa", options = {
    modulusLength: 4096,
    publicKeyEncoding: {
        type: "spki",
        format: "pem"
    },
    privateKeyEncoding: {
        type: "pkcs8",
        format: "pem"
    }
}) => {
    location = path.join(path.resolve("./"), location);
    if (!fs.existsSync(location)) {
        fs.writeFileSync(location, JSON.stringify(crypto.generateKeyPairSync(algorithm, options)))
    }
    const res = JSON.parse(fs.readFileSync(location).toString());
    publicKey = res.publicKey;
    privateKey = res.privateKey;
    return { publicKey, privateKey };
}
const sign = (sig) => {
    const signer = crypto.createSign("SHA256");
    signer.write(sig);
    signer.end();
    return signer.sign(privateKey).toString("base64");
}
const verify = (comp, sig, encoding = "base64") => {
    const verifier = crypto.createVerify("SHA256");
    verifier.write(comp);
    verifier.end();
    return verifier.verify(publicKey, Buffer.from(sig, encoding));
}
module.exports = {
    setup,
    sign,
    verify
}
