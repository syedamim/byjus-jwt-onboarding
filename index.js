'use strict';
const crypto = require("crypto");

const { generateToken, verifyToken, singInJwt } = require('./jwtServices');

const signToken = (payload, tllmsVerification, accessTokenInfo )=>{
    try{
        const nonce = crypto.randomBytes(16).toString("base64");
        const accessToken = generateToken(nonce, payload, tllmsVerification, accessTokenInfo);
        return accessToken;
    }catch(error){
        console.log("error in sign token ", error);
    }
}

module.exports = {
    signToken,
    verifyToken,
    singInJwt
};
