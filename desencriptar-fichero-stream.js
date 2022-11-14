const { Console } = require("console");
const { createDecipheriv, createECDH } = require("crypto");
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
var descifrador = createDecipheriv(algoritmo, secretKeyencriptFichero.slice(0, 32), secretKeyencriptFichero.slice(0, 16));
const inputFile = "./data/" + args.private + "-" + args.data + ".encr";
const outputFile = "./data/" + args.private + "-" + args.data + ".des";



fs.createReadStream(inputFile).pipe(descifrador).pipe(new fs.createWriteStream(outputFile))


// //encriptamos el fichero
// let ficheroDesencriptado = descifrador.update(ficheroxDesencriptar, 'hex','utf-8');
// //Para acabar con la encriptacion el fichero necesita una ultima operacion:
// ficheroDesencriptado+=descifrador.final("utf-8")
// console.log("fichero Desencriptado", ficheroDesencriptado);
// //guardamos el fichero desencriptado
// fs.writeFileSync(("./data/" + args.private + "-" + args.data + ".des"),ficheroDesencriptado)
