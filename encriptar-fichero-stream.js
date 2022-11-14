const { createCipheriv, createECDH } = require("crypto");
const { exit } = require("process");
const args = require('yargs').argv;
const fs = require('fs');

//Controlo si al lanzar el npx se ha proporcionado el parametro name
if (!args.private && !args.public && !args.data) {
    console.log("Faltan parametros");
    exit(0)
}

//Creamos la clave del remitente
const origenKey = createECDH("secp521r1");
console.log("origenKey", origenKey)

const keypvtRemitente = fs.readFileSync("./data/" + args.private + ".key").toString();
console.log("key pvt remitente", keypvtRemitente);

origenKey.setPrivateKey(keypvtRemitente, "hex");
console.log(origenKey.setPrivateKey(keypvtRemitente, "hex"));

//leo la public key del destinatario
const keypubDestino = fs.readFileSync("./data/" + args.public + ".pbk").toString();
console.log("key pub destino", keypubDestino);

//creamos la clave secreta para encriptar el fichero que es compartida con el destinatario
const secretKeyencriptFichero = Uint8Array.from(origenKey.computeSecret(keypubDestino, "hex", "hex"));
console.log(secretKeyencriptFichero)

/*cifrar el fichero eligiendo un algoritmo en este caso es el aes-256-cbc
creamos un cifrador con la funcion createCipheriv cuyos parametros son:
-el algoritmo, 
-los primeros 32 bits de la clave secreta 
-los primeros 16 bits de la clave secreta
*/
const algoritmo = "aes-256-cbc"
var cifrador = createCipheriv(algoritmo, secretKeyencriptFichero.slice(0, 32), secretKeyencriptFichero.slice(0, 16));

//Para los ficheros grande no se emplea el siguiente codigo que sirve para convertir el encriptado en hexadecimal
// cifrador.setEncoding("hex")

fs.createReadStream("./data/" + args.data).pipe(cifrador).pipe(new fs.createWriteStream("./data/"+args.public+"-"+args.data+".encr"))

