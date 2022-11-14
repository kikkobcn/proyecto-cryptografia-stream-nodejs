const { createECDH } = require('crypto'); //create ECDH crea la pareja de llaves
const args = require('yargs').argv
const fs = require('fs');   //Paquete que permite las operaciones con el hard diskx

console.log(args.name)

//Controlo si al lanzar el npx se ha proporcionado el parametro name
if (!args.name) {
    console.log("Falta el paramtro --name");
    exit(0)
}

const llaves = createECDH("secp521r1")
const pubKey=llaves.generateKeys("hex")
const pvtKey = llaves.getPrivateKey("hex")

fs.writeFileSync("./data/"+args.name+".key", pvtKey)
fs.writeFileSync("./data/"+args.name+".pbk", pubKey)