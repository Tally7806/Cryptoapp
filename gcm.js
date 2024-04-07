const GCM = (() => {
    let iv = null
    let useIV = true
    let Hmac = null
    
    const encrypt = (clearTextData, hashedPwd, useIV) => {
      
        if (useIV){
            let randomBytes   = CryptoJS.lib.WordArray.random(128/8).toString()
            iv = CryptoJS.enc.Hex.parse(randomBytes)
            console.log(`iv : ${iv}`)
            // old method (wrong) which used first 16 bytes of key (hashed pwd)
            // CryptoJS.enc.Hex.parse(key)
          message = CryptoJS.AES.encrypt(clearTextData, CryptoJS.enc.Hex.parse(hashedPwd),{iv: iv}) 
          console.log(`message.iv : ${message.iv}`)
          console.log(`message: ${message}`)
          console.log(`message.ciphertext ${message.ciphertext}`)
          console.log(`message.salt ${message.salt}`)
          }
          
        else{
          message = CryptoJS.AES.encrypt(clearTextData, hashedPwd )
        }
        
         return message.toString()
          
    }

    const decrypt = (encryptedData, hashedPwd, useIV) => {
     
        let code  
        if (useIV){
          console.log(`hashedPwd: ${hashedPwd}`)
          // we use original created iv
          // we now use the original _random_ iv which
          // is the correct way.  IV will be passed
          // in the clear to decrypting side
          // let iv = CryptoJS.enc.Hex.parse(key)
          console.log(`iv ${iv}`)
          code = CryptoJS.AES.decrypt(encryptedData, CryptoJS.enc.Hex.parse(hashedPwd),{iv:iv})
          console.log(`code ${code}`)
          //alert (typeof(code))
          console.log(code)
          }
        else{
          console.log("decrypting with no IV")
          code = CryptoJS.AES.decrypt(encryptedData, hashedPwd)
          console.log(code)
          
        }
        let decryptedMessage = ""
        if (code.sigBytes < 0){
          decryptedMessage = `Couldn't decrypt! It is probable that an incorrect password was used.`
          return decryptedMessage
        }
        
        decryptedMessage = code.toString(CryptoJS.enc.Utf8)
        return decryptedMessage     
         
    }

     const encryptFromText = () => {
      // Start the timer for encoding
      const encodeStartTime = performance.now();
        useIV = document.querySelector("#useIVCheckBox").checked
        let clearText = document.querySelector("#clear_text").value
        let cleartext_pwd = document.querySelector("#password").value
        let hashedPwd = sha256(cleartext_pwd)
        document.querySelector("#cleartext_output").innerHTML = ""
      
        document.querySelector("#cipher_output").innerHTML =  encrypt(clearText,hashedPwd,useIV)
        generateHmac()
         // End the timer for encoding
         const encodeEndTime = performance.now();

         // Calculate the elapsed time for encoding
         const encodeElapsedTime = encodeEndTime - encodeStartTime;
 
        // Display the elapsed time for encoding
        document.getElementById('encodeResult').innerHTML = `Encoding - Elapsed time: ${encodeElapsedTime} milliseconds`;
 
            return result;
       
    }

    const decryptFromText = () => {
       // Start the timer for decoding
    const decodeStartTime = performance.now();
        document.querySelector("#cleartext_output").innerHTML = ""
        useIV = document.querySelector("#useIVCheckBox").checked
        let cleartext_pwd = document.querySelector("#password").value
      
        let hashedPwd = sha256(cleartext_pwd)
        console.log(`hashedPwd: ${hashedPwd}`)
        
        // either get the cipher text from the input box or the div
        let cipherText = document.querySelector("#cipher_text").value
        if (cipherText == ""){
          cipherText = document.querySelector("#cipher_output").innerHTML
        }
        console.log(cleartext_pwd)
        document.querySelector("#cleartext_output").innerHTML = decrypt(cipherText,hashedPwd,useIV) 
          // End the timer for decoding
    const decodeEndTime = performance.now();

    // Calculate the elapsed time for decoding
    const decodeElapsedTime = decodeEndTime - decodeStartTime;

    // Display the elapsed time for decoding
    document.getElementById('decodeResult').innerHTML = `Decoding - Elapsed time: ${decodeElapsedTime} milliseconds`;

    return result;
           
    }

    const generateHmac = () => {
        let cleartext_pwd = document.querySelector("#password").value
        let encryptedData = document.querySelector("#cipher_output")
        let macKey = sha256(cleartext_pwd)
        console.log(`key: ${macKey}`)
        let hash = sha256.hmac(`${iv}:${encryptedData}`, macKey.toString())
        Hmac = hash
        console.log(`mac : ${Hmac}`)
        document.querySelector("#hmac").innerHTML = Hmac
    }

    const validate = () => {
        let output = "The MAC is valid."
        if (!validateMac()){
          output = "The MAC is NOT valid!"
        }
        document.querySelector("#validated").innerHTML = output
    }

    const validateMac = () => {
        // returns boolean (true if mac matches, otherwise false)
        let cleartext_pwd = document.querySelector("#password").value
        let encryptedData = document.querySelector("#cipher_output")
        let key = sha256(cleartext_pwd)
        let mac = sha256.hmac(`${iv}:${encryptedData}`, key.toString())
        console.log(`mac : ${mac}`)
        return (mac == Hmac)
    }

    return {
        encrypt: (clearTextData, hashedPwd, useIV) => encrypt(clearTextData, hashedPwd, useIV),
        decrypt: (encryptedData, hashedPwd, useIV) => decrypt(encryptedData, hashedPwd, useIV),
        encryptFromText: () => encryptFromText(),
        decryptFromText: () => decryptFromText(),
        generateHmac: () => generateHmac(),
        validate: () => validate(),
        validateMac: () => validateMac(),
        encryptFileData: () => encryptFileData(),
        fileToBinary: () => fileToBinary()
    }

})()