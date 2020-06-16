const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
let publicKey;
let privateKey;

module.exports={
    setup:(location)=>{
        location = path.join(__dirname, location).replace(`node_modules${path.sep}verlikify${path.sep}`,"");
        if (!fs.existsSync(location)){
            fs.writeFileSync(location, JSON.stringify(crypto.generateKeyPairSync("rsa", {
                modulusLength: 4096, 
                publicKeyEncoding: {
                    type: "spki",
                    format:"pem"
                },
                privateKeyEncoding:{
                    type: "pkcs8",
                    format: "pem"
                }
            })))
        }
        const res = JSON.parse(fs.readFileSync(location).toString());
        publicKey=res.publicKey;
        privateKey=res.privateKey;
        return {publicKey, privateKey};
    },
    sign:(sig)=>{
    const signer = crypto.createSign("SHA256");
    signer.write(sig);
    signer.end();
    return signer.sign(privateKey).toString("base64");
},
verify:(sig, comp, encoding="base64")=>{
    const verifier = crypto.createVerify("SHA256");
    verifier.write(comp);
    verifier.end();
    return verifier.verify(publicKey, Buffer.from(sig, encoding));
}
}
